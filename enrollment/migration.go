package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/novakiosk/agent/operations"
)

type migrationMarker struct {
	Version           int               `json:"version"`
	Profile           string            `json:"profile"`
	SourceUID         uint32            `json:"sourceUid"`
	EnrollmentID      string            `json:"enrollmentId"`
	PublicIdentityRef string            `json:"publicIdentityRef"`
	Files             map[string]string `json:"files"`
}

func openOwnedDirectory(path string, uid uint32) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !ownedMigrationFile(info, uid, 0700) {
		file.Close()
		return nil, fmt.Errorf("unsafe migration directory")
	}
	return file, nil
}
func ownedMigrationFile(info os.FileInfo, uid uint32, mode os.FileMode) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && info.Mode().Perm() == mode && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
func readOwnedAt(directory *os.File, name string, uid uint32) ([]byte, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedMigrationFile(info, uid, 0600) || info.Size() > maxRotationBytes {
		return nil, fmt.Errorf("unsafe migration record %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRotationBytes+1))
	if err != nil || len(data) > maxRotationBytes {
		return nil, fmt.Errorf("oversized migration record")
	}
	return data, nil
}
func writeOwnedAt(directory *os.File, name string, data []byte, uid, gid uint32) error {
	tmp := ".migration-next-" + name
	fd, err := syscall.Openat(int(directory.Fd()), tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), tmp)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("unsafe migration temporary")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != uid && stat.Uid != uint32(os.Geteuid())) {
		return fmt.Errorf("foreign migration temporary")
	}
	if os.Geteuid() == 0 {
		if err := file.Chown(int(uid), int(gid)); err != nil {
			return err
		}
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), tmp, int(directory.Fd()), name); err != nil {
		return err
	}
	return directory.Sync()
}

// MigrateLegacyAuthority is an attended root-only, fixed-root copy. Caller must
// first verify the legacy service is stopped. The mandatory rotation marker is
// committed before any identity bytes and normal daemon startup refuses it.
func MigrateLegacyAuthority(profile, expectedOrigin string, sourceUID, targetUID, targetGID uint32) error {
	if os.Geteuid() != 0 || sourceUID == targetUID || targetUID == 0 {
		return fmt.Errorf("migration requires root and distinct legacy/authority accounts")
	}
	source := "/var/lib/novakiosk-agent"
	if profile == "print-bridge" {
		source = "/var/lib/novakiosk-print-bridge"
	} else if profile != "kiosk" {
		return fmt.Errorf("unsupported migration profile")
	}
	return migrateAuthorityAt(source, "/var/lib/novakiosk-agentd", profile, expectedOrigin, sourceUID, targetUID, targetGID)
}
func migrateAuthorityAt(source, destination, profile, expectedOrigin string, sourceUID, targetUID, targetGID uint32) error {
	origin, err := CanonicalInstanceURL(expectedOrigin)
	if err != nil || origin != expectedOrigin {
		return fmt.Errorf("explicit canonical HTTPS migration origin required")
	}
	src, err := openOwnedDirectory(source, sourceUID)
	if err != nil {
		return err
	}
	defer src.Close()
	records := map[string][]byte{}
	for _, name := range []string{identityFilename, stateFilename, attemptFilename, operations.OperationJournalName, operations.FleetJournalName} {
		data, err := readOwnedAt(src, name, sourceUID)
		if errors.Is(err, os.ErrNotExist) && (name == attemptFilename || name == operations.OperationJournalName || name == operations.FleetJournalName) {
			continue
		}
		if err != nil {
			return err
		}
		records[name] = data
	}
	old, err := decodeIdentityMode(records[identityFilename], false)
	if err != nil {
		return fmt.Errorf("legacy identity needs attended repair under its original account: %w", err)
	}
	var state State
	if decodeStrictBounded(records[stateFilename], &state, maxRotationBytes) != nil || normalizeState(&state) != nil {
		return fmt.Errorf("invalid legacy managed state")
	}
	if state.InstanceURL != expectedOrigin {
		return fmt.Errorf("legacy source origin differs from operator-selected instance")
	}
	if state.Status != "Managed" {
		return fmt.Errorf("complete legacy approval/claim before migration; pending enrollment cannot rotate")
	}
	expectedKind := DeviceKindKiosk
	if profile == "print-bridge" {
		expectedKind = DeviceKindPrintServer
	}
	if state.DeviceKind != expectedKind || state.PublicIdentityRef != old.PublicIdentityRef || state.DeviceID != old.DeviceID {
		return fmt.Errorf("legacy identity/state/profile mismatch")
	}
	if raw, ok := records[attemptFilename]; ok {
		var request Request
		if decodeStrictBounded(raw, &request, maxRotationBytes) != nil || request.Version != 1 || request.Type != "bootstrap.enrollment" || request.DeviceID != state.DeviceID || request.Audience != expectedOrigin || request.IdempotencyKey == "" || request.Proof.Value == "" || ValidateDeviceKind(request.DeviceKind) != nil {
			return fmt.Errorf("invalid legacy pending request")
		}
	}
	if raw, ok := records[operations.OperationJournalName]; ok {
		if err := operations.ValidateResolvedJournal(raw, time.Now()); err != nil {
			return err
		}
	}
	if raw, ok := records[operations.FleetJournalName]; ok {
		if err := operations.ValidateResolvedFleetJournal(raw, time.Now()); err != nil {
			return err
		}
	}
	marker := migrationMarker{Version: 1, Profile: profile, SourceUID: sourceUID, EnrollmentID: state.EnrollmentID, PublicIdentityRef: old.PublicIdentityRef, Files: map[string]string{}}
	for name, data := range records {
		hash := sha256.Sum256(data)
		marker.Files[name] = hex.EncodeToString(hash[:])
	}
	markerData, _ := json.Marshal(marker)
	if err := os.Mkdir(destination, 0700); err == nil {
		if os.Geteuid() == 0 {
			if err := os.Chown(destination, int(targetUID), int(targetGID)); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	parent, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	dst, err := openOwnedDirectory(destination, targetUID)
	if err != nil {
		return err
	}
	defer dst.Close()
	fd, err := syscall.Openat(int(dst.Fd()), authorityLockFilename, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), authorityLockFilename)
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("unsafe destination lock")
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != targetUID && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("foreign destination lock")
	}
	if os.Geteuid() == 0 {
		if err := lock.Chown(int(targetUID), int(targetGID)); err != nil {
			return err
		}
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("stop daemon before migration")
	}
	previous, err := readOwnedAt(dst, migrationFilename, targetUID)
	resuming := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if resuming && !bytes.Equal(previous, markerData) {
		return fmt.Errorf("migration source changed; attended reconciliation required")
	}
	entries, err := dst.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range entries {
		if name == authorityLockFilename {
			continue
		}
		if !resuming {
			if name == ".migration-next-"+migrationFilename {
				if _, err := readOwnedAt(dst, name, targetUID); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("migration destination must be empty")
		}
		if name == migrationFilename || name == ".migration-next-"+migrationFilename {
			continue
		}
		raw, known := records[name]
		if !known {
			for allowed := range records {
				if name == ".migration-next-"+allowed {
					known = true
					break
				}
			}
			if known {
				if _, err := readOwnedAt(dst, name, targetUID); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("destination contains unrelated or active rotation state")
		}
		existing, err := readOwnedAt(dst, name, targetUID)
		if err != nil || !bytes.Equal(existing, raw) {
			return fmt.Errorf("migrated record differs from original source")
		}
	}
	// Recheck all source bytes under the same descriptors before admitting the
	// snapshot. Service-stop verification remains an attended prerequisite.
	for name, data := range records {
		again, err := readOwnedAt(src, name, sourceUID)
		if err != nil || !bytes.Equal(data, again) {
			return fmt.Errorf("legacy source changed during migration")
		}
	}
	if err := writeOwnedAt(dst, migrationFilename, markerData, targetUID, targetGID); err != nil {
		return err
	}
	for _, name := range []string{identityFilename, attemptFilename, operations.OperationJournalName, operations.FleetJournalName, stateFilename} {
		if data, ok := records[name]; ok {
			if err := writeOwnedAt(dst, name, data, targetUID, targetGID); err != nil {
				return err
			}
		}
	}
	return nil
}
