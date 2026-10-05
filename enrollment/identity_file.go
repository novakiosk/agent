package enrollment

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// The parent path must be trusted. All final components are opened without
// following symlinks, and file operations are anchored to the checked directory.
func identityDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	info, err := directory.Stat()
	if err != nil || !identityOwnership(info, 0o700) {
		directory.Close()
		return nil, fmt.Errorf("unsafe identity directory ownership or permissions")
	}
	return directory, nil
}

func identityOwnership(info os.FileInfo, mode os.FileMode) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == mode && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func readIdentityFile(path string) ([]byte, error) {
	return readPrivateRecord(path, identityFilename, 4096)
}

func readPrivateRecord(stateDir, name string, limit int) ([]byte, error) {
	directory, err := identityDirectory(stateDir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !identityOwnership(info, 0600) || info.Size() > int64(limit) {
		return nil, fmt.Errorf("unsafe private authority record")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, fmt.Errorf("authority record exceeds limit")
	}
	return data, nil
}

func writeIdentityFile(path string, data []byte) error {
	directory, err := identityDirectory(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	return writeIdentityAt(directory, data)
}

func writeIdentityAt(directory *os.File, data []byte) error {
	// O_EXCL also leaves interrupted writes visible for attended recovery.
	fd, err := syscall.Openat(int(directory.Fd()), "identity.pending", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "identity.pending")
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), "identity.pending", int(directory.Fd()), identityFilename); err != nil {
		return err
	}
	return directory.Sync()
}

// The authority lock is metadata, never evidence that a missing key may be
// regenerated. Any other entry (including pending creation) blocks first use.
func emptyIdentityDirectory(directory *os.File) error {
	names, err := directory.Readdirnames(2)
	if err != nil && err != io.EOF {
		return err
	}
	if len(names) == 0 {
		return nil
	}
	if len(names) != 1 || names[0] != authorityLockFilename {
		return fmt.Errorf("identity directory must be empty for explicit creation")
	}
	fd, err := syscall.Openat(int(directory.Fd()), authorityLockFilename, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), authorityLockFilename)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !identityOwnership(info, 0600) {
		return fmt.Errorf("unsafe authority lock")
	}
	return nil
}
