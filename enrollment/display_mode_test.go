package enrollment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDRMConnector(t *testing.T, root, name, status string) {
	t.Helper()
	connector := filepath.Join(root, name)
	if err := os.Mkdir(connector, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(connector, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestObserveDisplayModeClassifiesDRMConnectorEvidence(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
		want  DisplayMode
	}{
		{name: "physical", setup: func(t *testing.T, root string) {
			writeDRMConnector(t, root, "card0-HDMI-A-1", "disconnected\n")
			writeDRMConnector(t, root, "card0-DP-1", "connected\n")
		}, want: DisplayModePhysical},
		{name: "physical wins over earlier ambiguous evidence", setup: func(t *testing.T, root string) {
			writeDRMConnector(t, root, "card0-HDMI-A-1", "unknown\n")
			writeDRMConnector(t, root, "card0-DP-1", "connected\n")
		}, want: DisplayModePhysical},
		{name: "headless", setup: func(t *testing.T, root string) {
			writeDRMConnector(t, root, "card0-HDMI-A-1", "disconnected\n")
		}, want: DisplayModeHeadless},
		{name: "ambiguous status", setup: func(t *testing.T, root string) {
			writeDRMConnector(t, root, "card0-HDMI-A-1", "unknown\n")
		}, want: DisplayModeUnknown},
		{name: "no connectors", setup: func(*testing.T, string) {}, want: DisplayModeHeadless},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			testCase.setup(t, root)
			if got := ObserveDisplayModeAt(root); got != testCase.want {
				t.Fatalf("display mode = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestObserveDisplayModeFailsClosedForMalformedAndBoundedEvidence(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "missing status", setup: func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, "card0-HDMI-A-1"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "extra status bytes", setup: func(t *testing.T, root string) {
			writeDRMConnector(t, root, "card0-HDMI-A-1", strings.Repeat("connected", 8))
		}},
		{name: "ambiguous whitespace", setup: func(t *testing.T, root string) {
			writeDRMConnector(t, root, "card0-HDMI-A-1", "connected ")
		}},
		{name: "too many entries", setup: func(t *testing.T, root string) {
			for index := range drmMaxConnectors + 1 {
				name := "card0-DP-" + string(rune('A'+index%26)) + string(rune('0'+index/26))
				writeDRMConnector(t, root, name, "disconnected\n")
			}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			testCase.setup(t, root)
			if got := ObserveDisplayModeAt(root); got != DisplayModeUnknown {
				t.Fatalf("display mode = %q, want unknown", got)
			}
		})
	}
	if got := ObserveDisplayModeAt(filepath.Join(t.TempDir(), "missing")); got != DisplayModeUnknown {
		t.Fatalf("missing DRM root mode = %q, want unknown", got)
	}
}
