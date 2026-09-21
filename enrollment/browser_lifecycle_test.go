package enrollment

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The test executable provides a deterministic CDP child with real inherited
// pipes and process lifetime, without requiring Chromium or a compositor.
func TestMain(m *testing.M) {
	if os.Getenv("NOVA_TEST_CDP_CHILD") == "1" {
		input := bufio.NewReader(os.NewFile(3, "cdp-input"))
		output := os.NewFile(4, "cdp-output")
		current := "about:blank"
		for {
			data, err := readChromiumPipeMessage(input)
			if err != nil {
				os.Exit(0)
			}
			var command struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
				Params struct {
					URL string `json:"url"`
				} `json:"params"`
			}
			if json.Unmarshal(data, &command) != nil {
				os.Exit(1)
			}
			result := any(map[string]any{})
			switch command.Method {
			case "Target.getTargets":
				result = map[string]any{"targetInfos": []map[string]string{{"targetId": "page-1", "type": "page"}}}
			case "Target.attachToTarget":
				result = map[string]string{"sessionId": "attached-1"}
			case "Page.navigate":
				current = command.Params.URL
				if value := os.Getenv("NOVA_TEST_CDP_NAVIGATION_RESULT"); value != "" {
					result = json.RawMessage(value)
				}
				file, _ := os.OpenFile(os.Getenv("NOVA_TEST_CDP_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if file != nil {
					_, _ = file.WriteString(current + "\n")
					_ = file.Close()
				}
			case "Runtime.evaluate":
				result = map[string]any{"result": map[string]string{"value": current}}
			}
			response, _ := json.Marshal(map[string]any{"id": command.ID, "result": result})
			if _, err := output.Write(append(response, 0)); err != nil {
				os.Exit(0)
			}
		}
	}
	os.Exit(m.Run())
}

func TestRunObservesChildDeathAndRecreatesAppliedTarget(t *testing.T) {
	for _, test := range []struct {
		mode      string
		reconnect bool
	}{{"browser", false}, {"sway", false}, {"browser", true}, {"sway", true}} {
		mode := test.mode
		t.Run(fmt.Sprintf("%s/reconnect=%v", mode, test.reconnect), func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, test.reconnect)
			if mode == "sway" {
				fixture.runtime = runtimeDirectBrowserFixtureArtifact(false)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(t.TempDir(), "navigations")
			children := make(chan *chromiumBrowser, 4)
			var starts atomic.Int32
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- client.Run(ctx, RunOptions{RuntimeMode: mode, RuntimeApplier: &fakeRuntimeApplier{}, HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: time.Millisecond, BrowserFactory: func(ctx context.Context, profile string) (Browser, error) {
					starts.Add(1)
					child, err := NewChromiumBrowser(ctx, ChromiumOptions{Binary: binary, UserDataDir: profile, Environment: append(os.Environ(), "NOVA_TEST_CDP_CHILD=1", "NOVA_TEST_CDP_LOG="+log)})
					if err == nil {
						children <- child.(*chromiumBrowser)
					}
					return child, err
				}})
			}()
			for _, want := range []string{"applied", "failed", "applied"} {
				select {
				case ack := <-fixture.acks:
					if ack.Result != want {
						cancel()
						t.Fatalf("ACK result = %q, want %q", ack.Result, want)
					}
					if want == "applied" && starts.Load() == 1 {
						child := <-children
						if err := child.cmd.Process.Kill(); err != nil {
							t.Fatal(err)
						}
						select {
						case <-child.Done():
						case <-ctx.Done():
							t.Fatal("child was not reaped")
						}
					}
				case <-ctx.Done():
					t.Fatal("missing browser lifecycle ACK")
				}
			}
			cancel()
			<-done
			if starts.Load() != 2 {
				t.Fatalf("browser starts = %d", starts.Load())
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(data), "\n") != 2 {
				t.Fatalf("navigation history = %q", data)
			}
		})
	}
}

func TestManagedBrowserLaunchOptionsPreservePrintingWithoutKiosk(t *testing.T) {
	options := managedChromiumOptions("/usr/bin/chromium", "/var/lib/agent/browser", &RuntimeBrowserManagement{Kiosk: false, KioskPrinting: true})
	args := chromiumArguments(options)
	if !options.RequireGraphicalSession || !options.KioskConfigured || options.UserDataDir != "/var/lib/agent/browser" {
		t.Fatalf("launch options = %+v", options)
	}
	for _, arg := range args {
		if arg == "--kiosk" {
			t.Fatal("managed kiosk=false ignored")
		}
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--kiosk-printing") || !strings.Contains(joined, "--ozone-platform=wayland") {
		t.Fatalf("managed flags lost: %v", args)
	}
}

func TestChromiumNavigationRejectsFailedAndDownloadResults(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, result string
		wantError    bool
	}{
		{"success", `{"frameId":"page-1"}`, false},
		{"network-error", `{"frameId":"page-1","errorText":"net::ERR_CONNECTION_REFUSED"}`, true},
		{"download", `{"frameId":"page-1","isDownload":true}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			browser, err := NewChromiumBrowser(ctx, ChromiumOptions{
				Binary: binary, UserDataDir: filepath.Join(t.TempDir(), "browser"),
				Environment: append(os.Environ(), "NOVA_TEST_CDP_CHILD=1", "NOVA_TEST_CDP_NAVIGATION_RESULT="+test.result),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer browser.Close()
			// Even a matching location cannot override a failed navigation response.
			const target = "https://example.com/"
			observed, err := browser.Navigate(ctx, target)
			if test.wantError {
				if err == nil || observed != "" {
					t.Fatalf("failed navigation reported success: %q, %v", observed, err)
				}
			} else if err != nil || observed != target {
				t.Fatalf("successful navigation failed: %q, %v", observed, err)
			}
		})
	}
}
