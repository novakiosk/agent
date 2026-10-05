package enrollment

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
)

const rotationFilename = "identity-rotation.json"
const migrationFilename = "identity-migration.json"
const maxRotationBytes = 32768

type rotationJournal struct {
	Version      int                 `json:"version"`
	TransitionID string              `json:"transitionId"`
	InstanceURL  string              `json:"instanceUrl"`
	EnrollmentID string              `json:"enrollmentId"`
	OldBindingID string              `json:"oldBindingId"`
	OldIdentity  json.RawMessage     `json:"oldIdentity"`
	Candidate    json.RawMessage     `json:"candidate"`
	Transcript   *RotationTranscript `json:"transcript"`
	Result       *RotationResult     `json:"result"`
}

func writePrivateRecord(stateDir, name string, data []byte) error {
	if name != rotationFilename && name != identityFilename && name != migrationFilename {
		return fmt.Errorf("unsupported authority record")
	}
	if len(data) > maxRotationBytes {
		return fmt.Errorf("authority record exceeds limit")
	}
	directory, err := identityDirectory(stateDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	// Random temporary names permit attended recovery after any interrupted write;
	// only the fsync+rename result is authoritative, never a leftover temporary.
	temporary := ".authority-next-" + randomRotationID()
	fd, err := syscall.Openat(int(directory.Fd()), temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer syscall.Unlinkat(int(directory.Fd()), temporary)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), name); err != nil {
		return err
	}
	return directory.Sync()
}
func removePrivateRecord(stateDir, name string) error {
	if name != rotationFilename && name != migrationFilename {
		return fmt.Errorf("unsupported authority record")
	}
	directory, err := identityDirectory(stateDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return directory.Sync()
}
func saveRotation(stateDir string, journal rotationJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writePrivateRecord(stateDir, rotationFilename, data)
}

// RequireOrdinaryAuthority blocks daemon/session startup during an attended
// transition, including crashes between active bundle and enrollment writes.
func RequireOrdinaryAuthority(stateDir string) error {
	for _, name := range []string{rotationFilename, migrationFilename} {
		if _, err := readPrivateRecord(stateDir, name, maxRotationBytes); err == nil {
			return fmt.Errorf("%w: finish attended identity rotation before starting agentd", ErrIdentity)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: unsafe transition state: %v", ErrIdentity, err)
		}
	}
	return nil
}
