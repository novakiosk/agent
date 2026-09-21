package operations

import (
	"io/fs"
	"os"
	"path"
	"strings"
)

// FileSystem supplies read-only filesystem access for inventory and operation preflight.
type FileSystem interface {
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]fs.DirEntry, error)
	Lstat(string) (fs.FileInfo, error)
	Readlink(string) (string, error)
}

type hostFileSystem struct{}

func (hostFileSystem) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (hostFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}
func (hostFileSystem) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }
func (hostFileSystem) Readlink(name string) (string, error)   { return os.Readlink(name) }

func defaultFileSystem(value FileSystem) FileSystem {
	if value == nil {
		return hostFileSystem{}
	}
	return value
}

func filePresent(fileSystem FileSystem, name string) bool {
	info, err := fileSystem.Lstat(name)
	return err == nil && info != nil
}

func executablePresent(fileSystem FileSystem, name string) bool {
	info, err := fileSystem.Lstat(name)
	if err != nil || info == nil {
		return false
	}
	mode := info.Mode()
	return mode.IsRegular() && mode.Perm()&0111 != 0
}

func safeAbsolutePath(name string) bool {
	clean := path.Clean(name)
	return strings.HasPrefix(clean, "/") && clean == name && !strings.Contains(name, "\\") && !strings.Contains(name, "\x00") && !strings.HasPrefix(clean, "/../") && clean != "/.."
}
