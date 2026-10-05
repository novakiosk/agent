package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/novakiosk/agent/operations"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func legacyMigrationFixture(t *testing.T) (string, State) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(parent, "legacy")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentityAtomic(source, identity); err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Status: "Managed", DeviceKind: DeviceKindKiosk, InstanceURL: "https://control.example", EnrollmentID: "old-enrollment", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "old-binding", SessionID: "old-session", HeartbeatSequence: 97, FleetUpdateSequence: 42, LastHeartbeatAt: "2026-10-05T12:00:00Z"}
	if err := SaveStateAtomic(source, state); err != nil {
		t.Fatal(err)
	}
	return source, state
}
func TestAttendedMigrationCopiesOnlyAuthorityAndBlocksDaemon(t *testing.T) {
	source, state := legacyMigrationFixture(t)
	destination := filepath.Join(t.TempDir(), "authority")
	os.WriteFile(filepath.Join(source, "unrelated-browser-cookie"), []byte("do not copy"), 0600)
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", uid, uid, gid); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(destination)
	if err != nil || got.EnrollmentID != state.EnrollmentID || got.HeartbeatSequence != 97 || got.FleetUpdateSequence != 42 {
		t.Fatalf("state continuity: %+v %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(destination, "unrelated-browser-cookie")); !os.IsNotExist(err) {
		t.Fatal("copied mixed runtime state")
	}
	if err := RequireOrdinaryAuthority(destination); !errors.Is(err, ErrIdentity) {
		t.Fatal("unrotated migrated identity admitted")
	}
	before, _ := os.ReadFile(IdentityPath(source))
	after, _ := os.ReadFile(IdentityPath(destination))
	if !bytes.Equal(before, after) {
		t.Fatal("migration changed old key before rotation")
	}
	if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", uid, uid, gid); err != nil {
		t.Fatalf("idempotent interrupted migration: %v", err)
	}
	// Simulate a stop after mandatory marker but before the last state write.
	os.Remove(StatePath(destination))
	if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", uid, uid, gid); err != nil {
		t.Fatalf("partial copy recovery: %v", err)
	}
	state.HeartbeatSequence++
	if err := SaveStateAtomic(source, state); err != nil {
		t.Fatal(err)
	}
	if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", uid, uid, gid); err == nil {
		t.Fatal("changing legacy source silently replaced snapshot")
	}
}
func TestAttendedMigrationRejectsUnsafeOrPendingSource(t *testing.T) {
	for _, kind := range []string{"symlink", "owner", "pending", "destination", "origin"} {
		t.Run(kind, func(t *testing.T) {
			source, state := legacyMigrationFixture(t)
			destination := filepath.Join(t.TempDir(), "authority")
			uid := uint32(os.Geteuid())
			switch kind {
			case "symlink":
				data, _ := os.ReadFile(IdentityPath(source))
				target := filepath.Join(t.TempDir(), "identity")
				os.WriteFile(target, data, 0600)
				os.Remove(IdentityPath(source))
				os.Symlink(target, IdentityPath(source))
			case "owner":
				uid++
			case "origin":
				state.InstanceURL = "https://different.example"
				data, _ := json.Marshal(state)
				os.WriteFile(StatePath(source), data, 0600)
			case "pending":
				state.Status = "Pending"
				data, _ := json.Marshal(state)
				os.WriteFile(StatePath(source), data, 0600)
			case "destination":
				os.Mkdir(destination, 0700)
				os.WriteFile(filepath.Join(destination, "other"), []byte("retain"), 0600)
			}
			if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", uid, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
				t.Fatal("unsafe migration admitted")
			}
			if _, err := os.Stat(IdentityPath(destination)); !os.IsNotExist(err) {
				t.Fatal("rejection copied identity")
			}
		})
	}
}

func TestMigrationDifferentUIDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable rootless-container root")
	}
	root := t.TempDir()
	os.Chmod(filepath.Dir(root), 0755)
	os.Chmod(root, 0755)
	source := filepath.Join(root, "legacy")
	destination := filepath.Join(root, "authority")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentityAtomic(source, identity); err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Status: "Managed", DeviceKind: DeviceKindKiosk, InstanceURL: "https://control.example", EnrollmentID: "enrollment", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding", SessionID: "session", HeartbeatSequence: 3, LastHeartbeatAt: "2026-10-05T12:00:00Z"}
	if err := SaveStateAtomic(source, state); err != nil {
		t.Fatal(err)
	}
	request := Request{Version: 1, Type: "bootstrap.enrollment", IdempotencyKey: "fixture", DeviceID: state.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, Proof: Proof{Kind: identity.Profile(), Value: "fixture"}, Audience: state.InstanceURL, DeviceKind: DeviceKindKiosk}
	pending, _ := json.Marshal(request)
	os.WriteFile(attemptPath(source), pending, 0600)
	now := time.Now().UTC()
	command := operations.Command{Version: 1, Type: operations.CommandMessageType, CommandID: "00112233-4455-4677-8899-aabbccddeeff", CommandType: operations.CommandReboot, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	command.PayloadHash, _ = command.CanonicalPayloadHash()
	completed, _ := json.Marshal(map[string]any{"version": 1, "type": operations.OperationJournalType, "phase": operations.PhaseResultAccepted, "command": command, "result": operations.OperationResult{Version: 1, Type: operations.OperationType, CommandType: operations.CommandReboot, Result: operations.ResultScheduled, ObservedAt: now.Format(time.RFC3339Nano)}})
	os.WriteFile(operations.OperationJournalPath(source), completed, 0600)
	const oldUID, newUID = uint32(1201), uint32(1202)
	for _, name := range []string{identityFilename, stateFilename, attemptFilename, operations.OperationJournalName} {
		if err := os.Chown(filepath.Join(source, name), int(oldUID), int(oldUID)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(source, int(oldUID), int(oldUID)); err != nil {
		t.Fatal(err)
	}
	if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", oldUID, newUID, newUID); err != nil {
		t.Fatal(err)
	}
	os.Remove(StatePath(destination))
	if err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", oldUID, newUID, newUID); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(destination)
	if !ownedMigrationFile(info, newUID, 0700) {
		t.Fatal("destination ownership/mode")
	}
	for _, name := range []string{identityFilename, stateFilename, attemptFilename, operations.OperationJournalName, authorityLockFilename, migrationFilename} {
		info, err := os.Stat(filepath.Join(destination, name))
		if err != nil || !ownedMigrationFile(info, newUID, 0600) {
			t.Fatalf("copied record owner/mode %s: %v", name, err)
		}
	}
	for _, uid := range []uint32{oldUID, newUID} {
		command := exec.Command(os.Args[0], "-test.run=^TestMigrationUIDHelper$")
		command.Env = append(os.Environ(), "NOVA_MIGRATION_DEST="+destination)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		output, err := command.CombinedOutput()
		if uid == newUID && err != nil {
			t.Fatalf("daemon UID cannot read migrated authority: %v %s", err, output)
		}
		if uid == oldUID && err == nil {
			t.Fatal("legacy UID can read isolated destination")
		}
	}
}
func TestMigrationUIDHelper(t *testing.T) {
	destination := os.Getenv("NOVA_MIGRATION_DEST")
	if destination == "" {
		t.Skip("subprocess only")
	}
	if _, err := InspectIdentity(destination); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(destination); err != nil {
		t.Fatal(err)
	}
	if err := RequireOrdinaryAuthority(destination); !errors.Is(err, ErrIdentity) {
		t.Fatal("mandatory rotation not enforced under daemon UID")
	}
}
