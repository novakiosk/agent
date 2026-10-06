package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	browserValue, err := NewChromiumBrowser(ctx, idleChromiumOptions(options, profile, documentURL))
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
	if err := showIdleSurface(ctx, browser.cmd.Process.Pid, options.environment, ExecRuntimeCommandRunner{}); err != nil {
		return fmt.Errorf("show idle surface: %w", err)
	}
	if err := browser.WaitForIdleInput(ctx); err != nil {
		return fmt.Errorf("wait for idle input: %w", err)
	}
	return nil
}

func idleChromiumOptions(options IdleSurfaceOptions, profile, documentURL string) ChromiumOptions {
	return ChromiumOptions{
		Binary:      options.ChromiumBinary,
		UserDataDir: profile,
		// Native kiosk fullscreen would replace the presentation's workspace
		// fullscreen and make Chromium expose its toolbar after idle closes.
		// Map normally, then cover it with Sway's independent global fullscreen.
		KioskConfigured:         true,
		RequireGraphicalSession: true,
		Environment:             options.environment,
		InitialURL:              documentURL,
		// Retain kiosk UI behavior (including no exit-fullscreen hint) without
		// requesting native workspace fullscreen when the window maps.
		ExtraArgs: []string{"--force-app-mode"},
	}
}

type idleSwayNode struct {
	ID            int64          `json:"id"`
	PID           int            `json:"pid"`
	Type          string         `json:"type"`
	Nodes         []idleSwayNode `json:"nodes"`
	FloatingNodes []idleSwayNode `json:"floating_nodes"`
}

// showIdleSurface only changes the owned idle window. Keeping the underlying
// workspace fullscreen intact also makes SIGKILL/reapply safe: Sway uncovers
// the presentation when idle disappears, without a restoration command. A
// scratchpad global surface also makes Sway clear the overlay before choosing
// the next keyboard focus on destruction. Do not use scratchpad show: it would
// disable the presentation's workspace fullscreen.
func showIdleSurface(ctx context.Context, pid int, environment []string, runner RuntimeCommandRunner) error {
	if pid <= 0 {
		return errors.New("idle Chromium process is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := runner.Run(ctx, "/usr/bin/swaymsg", []string{"-r", "-t", "get_tree"}, environment)
		if err != nil {
			return fmt.Errorf("inspect idle window: %w", err)
		}
		var tree idleSwayNode
		if err := json.Unmarshal(data, &tree); err != nil || tree.Type != "root" {
			return errors.New("invalid Sway tree")
		}
		var matches []int64
		var visit func(idleSwayNode)
		visit = func(node idleSwayNode) {
			if (node.Type == "con" || node.Type == "floating_con") && node.PID == pid && node.ID > 0 {
				matches = append(matches, node.ID)
			}
			for _, child := range node.Nodes {
				visit(child)
			}
			for _, child := range node.FloatingNodes {
				visit(child)
			}
		}
		visit(tree)
		if len(matches) > 1 {
			return errors.New("idle Chromium has multiple windows")
		}
		if len(matches) == 1 {
			command := fmt.Sprintf("[con_id=%d pid=%d] move scratchpad, fullscreen enable global, focus", matches[0], pid)
			data, err := runner.Run(ctx, "/usr/bin/swaymsg", []string{"-r", command}, environment)
			if err != nil {
				return fmt.Errorf("display idle window: %w", err)
			}
			var results []struct {
				Success bool `json:"success"`
			}
			if err := json.Unmarshal(data, &results); err != nil || len(results) != 3 || !results[0].Success || !results[1].Success || !results[2].Success {
				return errors.New("Sway did not display and focus idle window")
			}
			return nil
		}
		// CDP can be ready before the Wayland window maps. This bounded startup
		// wait ends as soon as the one owned window appears; it is not a watchdog.
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
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
