package enrollment

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestChromiumPipeASCIIZFraming(t *testing.T) {
	message, err := readChromiumPipeMessage(bufio.NewReader(strings.NewReader("{\"id\":1}\x00")))
	if err != nil {
		t.Fatal(err)
	}
	if string(message) != `{"id":1}` {
		t.Fatalf("message = %q", message)
	}
}

func TestChromiumPipeASCIIZFramingBoundsNoTerminator(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, maxChromiumPipeMessage+2)
	_, err := readChromiumPipeMessage(bufio.NewReader(bytes.NewReader(data)))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized unterminated message error = %v", err)
	}
}

func TestChromiumPipeASCIIZFramingRejectsEOFWithoutTerminator(t *testing.T) {
	_, err := readChromiumPipeMessage(bufio.NewReader(strings.NewReader(`{"id":1}`)))
	if err == nil {
		t.Fatal("unterminated message was accepted")
	}
}

func TestManagedChromiumArgumentsAreGraphicalPipeOnly(t *testing.T) {
	args := chromiumArguments(ChromiumOptions{
		UserDataDir:             "/run/user/1000/nova-browser",
		Kiosk:                   true,
		KioskPrinting:           true,
		KioskConfigured:         true,
		RequireGraphicalSession: true,
		ExtraArgs:               []string{"--lang=en-US"},
	})
	want := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=/run/user/1000/nova-browser",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--kiosk",
		"--kiosk-printing",
		"--ozone-platform=wayland",
		"--lang=en-US",
		"about:blank",
	}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("managed Chromium args = %#v, want %#v", args, want)
	}
}

func TestIdleChromiumArgumentsAreIsolatedAndLocal(t *testing.T) {
	args := chromiumArguments(idleChromiumOptions(
		IdleSurfaceOptions{ChromiumBinary: "/usr/bin/chromium"},
		"/var/lib/novakiosk-agent/idle-profile", "file:///var/lib/novakiosk-agent/idle/idle.html"))
	for _, want := range []string{
		"--remote-debugging-pipe",
		"--user-data-dir=/var/lib/novakiosk-agent/idle-profile",
		"--ozone-platform=wayland",
		"--force-app-mode",
		"file:///var/lib/novakiosk-agent/idle/idle.html",
	} {
		found := slices.Contains(args, want)
		if !found {
			t.Fatalf("idle Chromium args %#v do not contain %q", args, want)
		}
	}
	for _, arg := range args {
		if arg == "--kiosk" || arg == "--start-fullscreen" || strings.HasPrefix(arg, "--remote-debugging-port") || strings.HasPrefix(arg, "--remote-debugging-address") || strings.Contains(arg, "http://") || strings.Contains(arg, "https://") {
			t.Fatalf("idle Chromium args contain native fullscreen or a network target: %q", arg)
		}
	}
}

func TestIdleChromiumNavigatesPrimaryTargetAndWaitsForMarker(t *testing.T) {
	commandRead, commandWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	responseRead, responseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer commandRead.Close()
	defer commandWrite.Close()
	defer responseRead.Close()
	defer responseWrite.Close()
	browser := &chromiumBrowser{command: commandWrite, response: responseRead, reader: bufio.NewReader(responseRead), id: 1, session: "idle-session"}
	serverResult := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(commandRead)
		for index, expectedMethod := range []string{"Page.navigate", "Runtime.evaluate", "Runtime.evaluate", "Runtime.evaluate", "Runtime.evaluate"} {
			payload, readErr := readChromiumPipeMessage(reader)
			if readErr != nil {
				serverResult <- readErr
				return
			}
			var request cdpEnvelope
			if json.Unmarshal(payload, &request) != nil || request.Method != expectedMethod {
				serverResult <- fmt.Errorf("request %d = %s", index, payload)
				return
			}
			if index == 0 && !strings.Contains(string(request.Params), `"url":"file:///var/lib/novakiosk-agent/idle/idle.html"`) {
				serverResult <- fmt.Errorf("navigate request = %s", request.Params)
				return
			}
			if index >= 2 && !strings.Contains(string(request.Params), idleInputMarkerExpression) {
				serverResult <- fmt.Errorf("marker request = %s", request.Params)
				return
			}
			result := json.RawMessage(`{}`)
			switch index {
			case 1:
				result = json.RawMessage(`{"result":{"value":"file:///var/lib/novakiosk-agent/idle/idle.html"}}`)
			case 2, 3:
				result = json.RawMessage(`{"result":{"value":false}}`)
			case 4:
				result = json.RawMessage(`{"result":{"value":true}}`)
			}
			response, _ := json.Marshal(cdpEnvelope{ID: request.ID, Result: result})
			if _, writeErr := responseWrite.Write(append(response, 0)); writeErr != nil {
				serverResult <- writeErr
				return
			}
		}
		serverResult <- nil
	}()
	if _, err := browser.NavigateIdleFile(context.Background(), "/var/lib/novakiosk-agent/idle/idle.html"); err != nil {
		t.Fatal(err)
	}
	if err := browser.WaitForIdleInput(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestBrowserEnvironmentDiscoversOnlyOwnedRealWaylandSocket(t *testing.T) {
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(runtimeDir, "wayland-9")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	socketInfo := func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return browserTestFileInfo{FileInfo: info, mode: os.ModeSocket}, nil
	}
	environment, err := browserEnvironment(ChromiumOptions{
		RequireGraphicalSession: true,
		Environment: []string{
			"XDG_RUNTIME_DIR=" + runtimeDir,
			"DISPLAY=:99",
			"WLR_BACKENDS=headless",
			"WLR_RENDERER=pixman",
		},
		waylandSocketInfo: socketInfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	env := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			env[key] = value
		}
	}
	if env["XDG_RUNTIME_DIR"] != runtimeDir || env["WAYLAND_DISPLAY"] != "wayland-9" || env["DISPLAY"] != ":99" {
		t.Fatalf("graphical environment = %#v", env)
	}
	for _, key := range []string{"WLR_BACKENDS", "WLR_RENDERER", "WLR_LIBINPUT_NO_DEVICES"} {
		if _, present := env[key]; present {
			t.Fatalf("unsafe compositor variable %s leaked", key)
		}
	}
	symlink := filepath.Join(runtimeDir, "wayland-link")
	if err := os.Symlink(socketPath, symlink); err != nil {
		t.Fatal(err)
	}
	if err := validateBrowserWaylandSocketWith(symlink, os.Lstat); err == nil {
		t.Fatal("symlink Wayland socket was accepted")
	}
}

func TestBrowserEnvironmentRejectsRuntimeDirectoryOwnedByAnotherUser(t *testing.T) {
	runtimeDir := t.TempDir()
	owner := uint32(os.Getuid() + 1)
	runtimeInfo := func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return browserTestFileInfo{FileInfo: info, owner: owner, ownerSet: true}, nil
	}
	_, err := browserEnvironment(ChromiumOptions{
		RequireGraphicalSession: true,
		Environment:             []string{"XDG_RUNTIME_DIR=" + runtimeDir, "WAYLAND_DISPLAY=wayland-1"},
		runtimeDirInfo:          runtimeInfo,
	})
	if err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") {
		t.Fatalf("wrong-owner runtime directory error = %v", err)
	}
}

type browserTestFileInfo struct {
	os.FileInfo
	mode     os.FileMode
	owner    uint32
	ownerSet bool
}

func (info browserTestFileInfo) Mode() os.FileMode {
	return info.FileInfo.Mode()&^os.ModeType | info.mode
}
func (info browserTestFileInfo) ModTime() time.Time { return info.FileInfo.ModTime() }
func (info browserTestFileInfo) Sys() any {
	owner := uint32(os.Getuid())
	if info.ownerSet {
		owner = info.owner
	}
	stat := &syscall.Stat_t{Uid: owner}
	return stat
}

// The pipe peer models native zoom separately from pinch scaling. A successful
// pinch command never changes native zoom, matching Chromium's old failure case.
type zoomCDPState struct {
	zoom, scale                                          float64
	pending                                              float64
	delayed                                              bool
	stuck, missingMetrics, metricError, failDown, failUp bool
	invalidURL                                           bool
	cancelDown                                           context.CancelFunc
	pressed                                              string
	downs, ups, pinchCommands                            int
}

func fakeZoomBrowser(t *testing.T, state *zoomCDPState) (*chromiumBrowser, func()) {
	t.Helper()
	commandRead, commandWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	responseRead, responseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	browser := &chromiumBrowser{command: commandWrite, response: responseRead, reader: bufio.NewReader(responseRead), id: 1, session: "zoom-session"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(commandRead)
		for {
			raw, err := readChromiumPipeMessage(reader)
			if err != nil {
				return
			}
			var request cdpEnvelope
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Error(err)
				return
			}
			result := any(map[string]any{})
			failure := ""
			switch request.Method {
			case "Page.getLayoutMetrics":
				if state.metricError {
					failure = "metrics unavailable"
					break
				}
				if state.missingMetrics {
					break
				}
				if state.pending != 0 {
					if state.delayed {
						state.delayed = false
					} else {
						state.zoom = state.pending
						state.pending = 0
					}
				}
				result = map[string]any{"cssVisualViewport": map[string]any{"zoom": state.zoom, "scale": state.scale}}
			case "Input.dispatchKeyEvent":
				var key struct {
					Type, Key, Code                                        string
					Modifiers, WindowsVirtualKeyCode, NativeVirtualKeyCode int
				}
				if err := json.Unmarshal(request.Params, &key); err != nil {
					t.Error(err)
					return
				}
				expectedCode, expectedVK := "Equal", 187
				if key.Key == "-" {
					expectedCode, expectedVK = "Minus", 189
				}
				if key.Key == "0" {
					expectedCode, expectedVK = "Digit0", 48
				}
				if key.Modifiers != 2 || key.Code != expectedCode || key.WindowsVirtualKeyCode != expectedVK || key.NativeVirtualKeyCode != expectedVK {
					t.Errorf("wrong native key parameters: %s", request.Params)
				}
				if key.Type == "keyUp" {
					state.ups++
					if state.pressed != key.Key {
						t.Errorf("unpaired key release %s", key.Key)
					}
					state.pressed = ""
					if state.failUp {
						failure = "release failed"
					}
				} else {
					state.downs++
					if state.pressed != "" {
						t.Error("previous key was not released")
					}
					state.pressed = key.Key
					if state.cancelDown != nil {
						state.cancelDown()
					}
					if state.failDown {
						failure = "key failed"
						break
					}
					if state.stuck {
						break
					}
					levels := []float64{0.5, 2.0 / 3, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2}
					next := 1.0
					if key.Key != "0" {
						for index, value := range levels {
							if math.Abs(value-state.zoom) < 0.001 {
								if key.Key == "-" && index > 0 {
									next = levels[index-1]
								} else if key.Key == "+" && index+1 < len(levels) {
									next = levels[index+1]
								}
								break
							}
						}
					}
					state.pending = next
					state.delayed = true
				}
			case "Emulation.setPageScaleFactor":
				state.pinchCommands++
				var params struct{ PageScaleFactor float64 }
				_ = json.Unmarshal(request.Params, &params)
				state.scale = math.Max(1, params.PageScaleFactor)
			case "Runtime.evaluate":
				target := "https://example.com/"
				if state.invalidURL {
					target = "data:text/html,invalid"
				}
				result = map[string]any{"result": map[string]any{"value": target}}
			default:
				failure = "unexpected method " + request.Method
			}
			response := map[string]any{"id": request.ID, "result": result}
			if failure != "" {
				delete(response, "result")
				response["error"] = map[string]string{"message": failure}
			}
			encoded, _ := json.Marshal(response)
			if _, err := responseWrite.Write(append(encoded, 0)); err != nil {
				return
			}
		}
	}()
	var once sync.Once
	finish := func() {
		once.Do(func() { _ = browser.Close(); _ = commandRead.Close(); _ = responseWrite.Close(); <-done })
	}
	t.Cleanup(finish)
	return browser, finish
}

func TestChromiumNativeZoomAllAllowedLevels(t *testing.T) {
	for _, percent := range []int{50, 67, 75, 80, 90, 100, 110, 125, 150, 175, 200} {
		t.Run(strconv.Itoa(percent), func(t *testing.T) {
			state := &zoomCDPState{zoom: 1.75, scale: 1.5}
			browser, finish := fakeZoomBrowser(t, state)
			url, observed, err := browser.SetZoom(context.Background(), percent)
			if err != nil || url != "https://example.com/" || observed != percent {
				t.Fatalf("zoom=%d url=%s error=%v", observed, url, err)
			}
			finish()
			if int(math.Round(state.zoom*100)) != percent || state.scale != 1 || state.pinchCommands != 1 || state.downs != state.ups || state.downs > 6 {
				t.Fatalf("unobserved zoom or incomplete/beyond-bound key flow: %+v", state)
			}
		})
	}
}

func TestChromiumNativeZoomRejectsUnobservedResults(t *testing.T) {
	for _, kind := range []string{"stuck", "missing", "invalid", "metrics-error", "keydown-error", "keyup-error", "cancel-keydown", "invalid-url", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := &zoomCDPState{zoom: 1, scale: 1}
			switch kind {
			case "stuck":
				state.stuck = true
			case "missing":
				state.missingMetrics = true
			case "invalid":
				state.zoom = -1
			case "metrics-error":
				state.metricError = true
			case "keydown-error":
				state.failDown = true
			case "keyup-error":
				state.failUp = true
			case "cancel-keydown":
				state.cancelDown = cancel
			case "invalid-url":
				state.invalidURL = true
			case "canceled":
				cancel()
			}
			browser, finish := fakeZoomBrowser(t, state)
			url, observed, err := browser.SetZoom(ctx, 50)
			if err == nil || url != "" || observed != 0 {
				t.Fatalf("false success: %s %d %v", url, observed, err)
			}
			finish()
			if state.downs != state.ups {
				t.Fatalf("key left pressed after failure: %+v", state)
			}
			if kind == "canceled" && state.downs != 0 {
				t.Fatal("canceled zoom dispatched a key")
			}
		})
	}
}

func TestChromiumUsesManagedCUPSDefaultInsteadOfInheritedOverrides(t *testing.T) {
	env, err := browserEnvironment(ChromiumOptions{Environment: []string{"HOME=/home/kiosk", "LPDEST=PDF", "PRINTER=Other", "CUPS_SERVER=other-host", "LANG=en_US.UTF-8"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(env, "\n") != "HOME=/home/kiosk\nLANG=en_US.UTF-8" {
		t.Fatalf("inherited printer override: %v", env)
	}
}
