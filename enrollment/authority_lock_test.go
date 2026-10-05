package enrollment

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAuthorityLockSerializesEnrollmentAndDaemon(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lock, err := AcquireAuthorityLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := AcquireAuthorityLock(dir); err == nil {
		second.Close()
		t.Fatal("concurrent authority writer admitted")
	}
	if _, err := CreateSoftwareIdentity(dir, "opaque-device-id"); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	second, err := AcquireAuthorityLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.Close()
}
func TestConcurrentLegacyCreationDoesNotReplaceIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	var group sync.WaitGroup
	successes := make(chan Identity, 16)
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if identity, err := LoadOrCreateIdentity(dir); err == nil {
				successes <- identity
			}
		}()
	}
	group.Wait()
	close(successes)
	persisted, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for identity := range successes {
		count++
		if identity.PublicIdentityRef != persisted.PublicIdentityRef {
			t.Fatal("successful creator's key was overwritten")
		}
	}
	if count == 0 {
		t.Fatal("no creator succeeded")
	}
}
func TestAuthorityLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, authorityLockFilename)); err != nil {
		t.Fatal(err)
	}
	if lock, err := AcquireAuthorityLock(dir); err == nil {
		lock.Close()
		t.Fatal("symlink lock accepted")
	}
}
