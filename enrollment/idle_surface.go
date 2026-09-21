package enrollment

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	idleDirectoryName = "idle"
	idleDocumentName  = "idle.html"
	idleProfileName   = "idle-profile"
	maxIdleHTMLBytes  = 4 * 1024 * 1024
)

// IdleSurfaceOptions contains the only inputs accepted by the disposable
// idle-surface process. The command derives its document and profile paths
// from StateDir; callers cannot select an arbitrary HTML file or profile.
type IdleSurfaceOptions struct {
	StateDir       string
	ChromiumBinary string

	// environment is a package test seam. The command always inherits its
	// actual graphical-session environment in production.
	environment []string
}

// RunIdleSurface launches the isolated Chromium surface, navigates its one
// primary page target to the atomically installed local document, and blocks
// until that document observes real user input. It never reaches the managed
// presentation browser or its profile.
func RunIdleSurface(ctx context.Context, options IdleSurfaceOptions) (returnErr error) {
	if err := validateIdleStateRoot(options.StateDir); err != nil {
		return err
	}
	idleDirectory := filepath.Join(options.StateDir, idleDirectoryName)
	if err := ensureIdleDirectory(idleDirectory); err != nil {
		return fmt.Errorf("idle state directory: %w", err)
	}
	document := filepath.Join(idleDirectory, idleDocumentName)
	if err := validateIdleDocumentPath(document); err != nil {
		return err
	}
	if err := validateIdleDocumentFile(document); err != nil {
		return err
	}
	if data, err := os.ReadFile(document); err != nil {
		return fmt.Errorf("read idle document: %w", err)
	} else if len(data) == 0 || len(data) > maxIdleHTMLBytes {
		return errors.New("idle document size is invalid")
	}

	profile := filepath.Join(options.StateDir, idleProfileName)
	if err := removeDisposableIdleProfile(profile); err != nil {
		return fmt.Errorf("clean idle Chromium profile: %w", err)
	}
	if err := os.Mkdir(profile, 0o700); err != nil {
		return fmt.Errorf("create idle Chromium profile: %w", err)
	}
	if err := ensureDisposableIdleProfile(profile); err != nil {
		return err
	}

	documentURL := (&url.URL{Scheme: "file", Path: document}).String()
	browserValue, err := NewChromiumBrowser(ctx, ChromiumOptions{
		Binary:                  options.ChromiumBinary,
		UserDataDir:             profile,
		Kiosk:                   true,
		KioskConfigured:         true,
		RequireGraphicalSession: true,
		Environment:             options.environment,
		InitialURL:              documentURL,
	})
	if err != nil {
		_ = removeDisposableIdleProfile(profile)
		return fmt.Errorf("start idle Chromium: %w", err)
	}
	browser, ok := browserValue.(*chromiumBrowser)
	if !ok || browser == nil {
		_ = browserValue.Close()
		_ = removeDisposableIdleProfile(profile)
		return errors.New("idle Chromium control is unavailable")
	}
	defer func() {
		if err := browser.Close(); returnErr == nil && err != nil {
			returnErr = fmt.Errorf("close idle Chromium: %w", err)
		}
		if err := removeDisposableIdleProfile(profile); returnErr == nil && err != nil {
			returnErr = fmt.Errorf("clean idle Chromium profile: %w", err)
		}
	}()
	if _, err := browser.NavigateIdleFile(ctx, document); err != nil {
		return fmt.Errorf("navigate idle document: %w", err)
	}
	if err := browser.WaitForIdleInput(ctx); err != nil {
		return fmt.Errorf("wait for idle input: %w", err)
	}
	return nil
}

func validateIdleStateRoot(path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || !safeIdlePath(path) {
		return errors.New("idle state directory must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("idle state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("idle state directory must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("protect idle state directory: %w", err)
		}
		info, err = os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			return errors.New("idle state directory must have mode 0700")
		}
	}
	return nil
}

func ensureIdleDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("directory must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect directory: %w", err)
	}
	return nil
}

func validateIdleDocumentPath(path string) error {
	clean := filepath.Clean(path)
	if clean != path || !filepath.IsAbs(path) || !safeIdlePath(path) || filepath.Base(path) != idleDocumentName || filepath.Base(filepath.Dir(path)) != idleDirectoryName {
		return errors.New("idle document path is invalid")
	}
	return nil
}

func validateIdleDocumentFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("idle document: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("idle document must be a regular local file")
	}
	if info.Mode().Perm() != 0o600 {
		return errors.New("idle document must have mode 0600")
	}
	return nil
}

func ensureDisposableIdleProfile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect idle Chromium profile: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("idle Chromium profile must be a real mode-0700 directory")
	}
	return nil
}

func removeDisposableIdleProfile(path string) error {
	if filepath.Base(path) != idleProfileName || !filepath.IsAbs(path) || filepath.Clean(path) != path || !safeIdlePath(path) {
		return errors.New("idle Chromium profile path is invalid")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("idle Chromium profile must be a real directory")
	}
	return os.RemoveAll(path)
}

func safeIdlePath(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func idleShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func resolveAgentBinary() string {
	if executable, err := os.Executable(); err == nil && safeIdleBinary(executable) {
		return executable
	}
	return "/usr/local/bin/novakiosk-agent"
}
