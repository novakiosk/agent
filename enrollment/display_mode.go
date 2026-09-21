package enrollment

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DisplayMode is the bounded display evidence reported by a managed kiosk.
// Unknown is deliberately fail-open for idle suppression: only a signed
// headless observation suppresses an idle screen.
type DisplayMode string

const (
	DisplayModePhysical DisplayMode = "physical"
	DisplayModeHeadless DisplayMode = "headless"
	DisplayModeUnknown  DisplayMode = "unknown"
)

func (mode DisplayMode) Valid() bool {
	return mode == DisplayModePhysical || mode == DisplayModeHeadless || mode == DisplayModeUnknown
}

const (
	drmDisplayRoot       = "/sys/class/drm"
	drmMaxConnectors     = 64
	drmMaxConnectorBytes = 128
	drmMaxStatusBytes    = 32
)

var drmConnectorName = regexp.MustCompile(`^card[0-9]+-[A-Za-z0-9_.-]+$`)

// ObserveDisplayMode reads the same DRM connector status files used by the
// image's start-sway.sh. It performs no command execution and keeps directory
// and file reads bounded. A connected connector wins over all other evidence;
// otherwise an unambiguous readable DRM directory establishes headless mode,
// including when it has no matching connectors.
func ObserveDisplayMode() DisplayMode {
	return ObserveDisplayModeAt(drmDisplayRoot)
}

// ObserveDisplayModeAt is a testable variant of ObserveDisplayMode. The path
// is expected to be a directory containing card*-* connector entries.
func ObserveDisplayModeAt(root string) DisplayMode {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return DisplayModeUnknown
	}
	directory, err := os.Open(root)
	if err != nil {
		return DisplayModeUnknown
	}
	defer directory.Close()

	entries, err := directory.Readdirnames(drmMaxConnectors + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return DisplayModeUnknown
	}
	if len(entries) > drmMaxConnectors {
		return DisplayModeUnknown
	}
	ambiguous := false
	for _, name := range entries {
		if len(name) == 0 || len(name) > drmMaxConnectorBytes || !drmConnectorName.MatchString(name) {
			continue
		}
		info, infoErr := os.Stat(filepath.Join(root, name))
		if infoErr != nil || !info.IsDir() {
			ambiguous = true
			continue
		}
		status, readErr := readDRMStatus(filepath.Join(root, name, "status"))
		if readErr != nil {
			// A connector-shaped entry that cannot be read is ambiguous. Do not
			// call a machine headless merely because another connector is absent.
			ambiguous = true
			continue
		}
		switch status {
		case "connected":
			// A connected connector wins over any earlier ambiguous evidence.
			return DisplayModePhysical
		case "disconnected":
			// Keep looking: another connector may be connected.
		default:
			// DRM's "unknown" status and malformed values are ambiguous.
			ambiguous = true
		}
	}
	if ambiguous {
		return DisplayModeUnknown
	}
	// start-sway.sh treats a readable DRM directory with no connected
	// connector as headless. A directory containing only unrelated entries
	// therefore still provides the same no-monitor evidence.
	return DisplayModeHeadless
}

func readDRMStatus(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("DRM status is not a regular readable file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, drmMaxStatusBytes+1))
	if err != nil || len(data) > drmMaxStatusBytes {
		return "", errors.New("DRM status is unreadable or oversized")
	}
	// Sysfs status files normally end in one LF. Match grep '^connected$'
	// semantics while rejecting whitespace and additional records.
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	status := string(data)
	if strings.ContainsAny(status, "\r\n") {
		return "", errors.New("DRM status is ambiguous")
	}
	return status, nil
}
