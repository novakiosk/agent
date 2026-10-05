package enrollment

import (
	"fmt"
	"os"
	"syscall"
)

const authorityLockFilename = ".authority.lock"

// AcquireAuthorityLock serializes attended enrollment/rotation and daemon
// authority writes. It is nonblocking so an operator gets an actionable error.
func AcquireAuthorityLock(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	directory, err := identityDirectory(stateDir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := syscall.Openat(int(directory.Fd()), authorityLockFilename, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), authorityLockFilename)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !identityOwnership(info, 0600) {
		file.Close()
		return nil, fmt.Errorf("unsafe authority lock")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("device authority is busy; stop agentd before attended changes")
	}
	return file, nil
}
