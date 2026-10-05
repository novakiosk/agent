package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type fakeIdleProcess struct {
	killed bool
	exited bool
	waited bool
	pid    int
}

func (process *fakeIdleProcess) Wait() error { process.waited = true; return nil }
func (process *fakeIdleProcess) Kill() error { process.killed = true; return nil }
func (process *fakeIdleProcess) Alive() bool { return !process.killed && !process.exited }
func (process *fakeIdleProcess) PID() int    { return process.pid }

type idleRunnerCall struct {
	name        string
	args        []string
	environment []string
}

type fakeIdleRunner struct {
	starts    []idleRunnerCall
	processes []*fakeIdleProcess
}

func (runner *fakeIdleRunner) Start(_ context.Context, name string, args, environment []string) (idleProcess, error) {
	process := &fakeIdleProcess{pid: 4200 + len(runner.processes)}
	runner.starts = append(runner.starts, idleRunnerCall{name: name, args: append([]string(nil), args...), environment: append([]string(nil), environment...)})
	runner.processes = append(runner.processes, process)
	return process, nil
}

func TestIdleCommandRunnerOwnsProcessGroup(t *testing.T) {
	process, err := (execIdleCommandRunner{}).Start(context.Background(), "/bin/sleep", []string{"30"}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = process.Kill()
		_ = process.Wait()
	}()
	processGroupID, err := syscall.Getpgid(process.PID())
	if err != nil {
		t.Fatal(err)
	}
	if processGroupID != process.PID() {
		t.Fatalf("idle process group = %d, want child PID %d", processGroupID, process.PID())
	}
}

func TestIdleCommandRunnerCancellationKillsChildBeforeRearm(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child.pid")
	command := "sleep 30 & child=$!; printf '%s' \"$child\" > " + idleShellQuote(marker) + "; wait \"$child\""
	process, err := (execIdleCommandRunner{}).Start(context.Background(), "/bin/sh", []string{"-c", command}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if process.Alive() {
			_ = process.Kill()
		}
		_ = process.Wait()
	}()
	var childPID int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(marker)
		if readErr == nil {
			if _, scanErr := fmt.Sscanf(string(data), "%d", &childPID); scanErr == nil && childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("child PID marker was not written")
	}
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil && !strings.Contains(err.Error(), "signal: killed") {
		t.Fatalf("wait after process-group cancellation: %v", err)
	}
	childGone := false
	childDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(childDeadline) {
		if errors.Is(syscall.Kill(childPID, 0), syscall.ESRCH) {
			childGone = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !childGone {
		t.Fatalf("idle child still exists after group cancellation")
	}
}

func testIdleDesired(t *testing.T) IdleDesired {
	t.Helper()
	desired := IdleDesired{Type: IdleDesiredType, IdleScreenID: "idle-1", RevisionID: "revision-1", Revision: 1, TimeoutSeconds: 60, BackgroundColor: "#112233", Logos: []IdleLogo{}, VideoURL: nil, CanvasAspect: "16:9", Texts: []IdleTextBlock{{ID: "idle-text-1", Text: "Welcome & wait", Color: "#FFFFFF", Font: "sans", FontSizePercent: 8, FontWeight: "normal", TextAlign: "center", XPercent: 50, YPercent: 50}}}
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	return desired
}

func TestIdleDesiredAllowsEmptyTextBlocks(t *testing.T) {
	desired := testIdleDesired(t)
	desired.Texts = []IdleTextBlock{}
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	if err := ValidateIdleDesired(desired); err != nil {
		t.Fatal(err)
	}
	if _, err := IdleHTML(desired); err != nil {
		t.Fatal(err)
	}
}

func TestIdleHTMLRendersEscapedContentAndCanvas(t *testing.T) {
	desired := testIdleDesired(t)
	video := "https://iframe.mediadelivery.net/embed/123456/00000000-0000-4000-8000-000000000001?autoplay=true&loop=true&muted=true"
	desired.VideoURL = &video
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	html, err := IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Welcome &amp; wait") || strings.Contains(string(html), "Welcome & wait</main>") {
		t.Fatalf("idle HTML did not escape text: %s", html)
	}
	if !strings.Contains(string(html), `src="https://iframe.mediadelivery.net/embed/123456/00000000-0000-4000-8000-000000000001?autoplay=true&amp;loop=true&amp;muted=true"`) {
		t.Fatalf("idle HTML did not embed the canonical Bunny player URL: %s", html)
	}
	if !strings.Contains(string(html), `class="idle-canvas aspect-landscape"`) || !strings.Contains(string(html), "width:min(100vw,177.7777778vh)") || !strings.Contains(string(html), "aspect-ratio:16/9") || !strings.Contains(string(html), "font-size:8cqmin") {
		t.Fatalf("landscape idle HTML does not preserve the authored canvas or container-relative text size: %s", html)
	}
	legacy := strings.ReplaceAll(video, "=true", "=1")
	desired.VideoURL = &legacy
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	if _, err := IdleHTML(desired); err == nil {
		t.Fatal("legacy numeric Bunny playback query was accepted by the kiosk")
	}
	desired = testIdleDesired(t)
	desired.CanvasAspect = "9:16"
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	portrait, err := IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(portrait), `class="idle-canvas aspect-portrait"`) || !strings.Contains(string(portrait), `data-canvas-aspect="9:16"`) || !strings.Contains(string(portrait), "width:min(100vw,56.25vh)") || !strings.Contains(string(portrait), "aspect-ratio:9/16") {
		t.Fatalf("portrait idle HTML does not preserve the authored canvas ratio: %s", portrait)
	}
}

func TestIdleFontsAreBoundedAndRenderedFromCatalog(t *testing.T) {
	expectedIDs := []string{
		"sans", "serif", "monospace",
		"adwaita-sans", "cantarell", "open-sans", "droid-sans", "liberation-sans", "noto-sans", "nimbus-sans", "nimbus-sans-narrow", "urw-gothic",
		"liberation-serif", "noto-serif", "nimbus-roman", "urw-bookman", "stix-two-text",
		"adwaita-mono", "liberation-mono", "noto-sans-mono", "nimbus-mono-ps",
		"vazirmatn", "noto-naskh-arabic", "padauk", "jomolhari", "noto-sans-cjk-jp", "noto-sans-cjk-kr", "noto-sans-cjk-sc", "noto-sans-cjk-tc", "noto-sans-cjk-hk",
	}
	if len(idleFontCSSStacks) != len(expectedIDs) {
		t.Fatalf("idle font catalog has %d IDs, want %d", len(idleFontCSSStacks), len(expectedIDs))
	}
	for _, id := range expectedIDs {
		if _, ok := idleFontCSSStacks[id]; !ok {
			t.Fatalf("idle font catalog is missing %q", id)
		}
	}
	for id, stack := range idleFontCSSStacks {
		t.Run(id, func(t *testing.T) {
			desired := testIdleDesired(t)
			desired.Texts[0].Font = id
			desired.PayloadHash = IdleScreenPayloadHash(desired)
			html, err := IdleHTML(desired)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(html), `font-family:`+stack+`;`) {
				t.Fatalf("font %q did not render mapped stack %q: %s", id, stack, html)
			}
		})
	}
	desired := testIdleDesired(t)
	desired.Texts[0].Font = "system-ui"
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	if err := ValidateIdleDesired(desired); err == nil {
		t.Fatal("unknown idle font was accepted")
	}
}

func idleCacheTestDesired(t *testing.T, data []byte, mime string) (IdleDesired, string) {
	t.Helper()
	digest := sha256.Sum256(data)
	logo := IdleLogo{ID: "asset-id", SHA256: hex.EncodeToString(digest[:]), MIME: mime, SizeBytes: uint64(len(data)), DisplayName: "brand", Position: "top-left", WidthPercent: 20}
	desired := IdleDesired{Type: IdleDesiredType, IdleScreenID: "idle-assets", RevisionID: "revision-assets", Revision: 1, TimeoutSeconds: 60, BackgroundColor: "#112233", Logos: []IdleLogo{logo}, CanvasAspect: "16:9", Texts: []IdleTextBlock{{ID: "idle-text-1", Text: "Welcome", Color: "#FFFFFF", Font: "sans", FontSizePercent: 8, FontWeight: "normal", TextAlign: "center", XPercent: 50, YPercent: 50}}}
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	return desired, logo.SHA256
}

func testAssetPNG(t *testing.T) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testAssetJPEG() []byte {
	data := []byte{0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00}
	data = append(data, bytes.Repeat([]byte{1}, 64)...)
	data = append(data, []byte{0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x00, 0xff, 0xd9}...)
	return data
}

func testAssetWebP() []byte {
	return []byte{0x52, 0x49, 0x46, 0x46, 0x12, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50, 0x38, 0x4c, 0x05, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00}
}

func testAssetWebPWithEXIF() []byte {
	return []byte{
		0x52, 0x49, 0x46, 0x46, 0x30, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
		0x56, 0x50, 0x38, 0x58, 0x0a, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x56, 0x50, 0x38, 0x4c, 0x05, 0x00, 0x00, 0x00, 0x2f, 0, 0, 0, 0, 0,
		0x45, 0x58, 0x49, 0x46, 0x04, 0x00, 0x00, 0x00, 1, 2, 3, 4,
	}
}

func TestIdleAssetContainerValidationIsStrictAndBounded(t *testing.T) {
	png := testAssetPNG(t)
	jpeg := testAssetJPEG()
	webp := testAssetWebP()
	webpEXIF := testAssetWebPWithEXIF()
	for _, testCase := range []struct {
		name string
		data []byte
		mime string
	}{
		{name: "png", data: png, mime: "image/png"},
		{name: "jpeg", data: jpeg, mime: "image/jpeg"},
		{name: "webp", data: webp, mime: "image/webp"},
		{name: "webp with exif", data: webpEXIF, mime: "image/webp"},
	} {
		if !validIdleAssetBytes(testCase.data, testCase.mime) {
			t.Errorf("valid %s fixture was rejected", testCase.name)
		}
	}
	iend := []byte{0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82}
	brokenCRC := append([]byte(nil), png...)
	brokenCRC[29] ^= 0xff
	missingIDAT := append(append([]byte(nil), png[:33]...), iend...)
	trailing := append(append([]byte(nil), png...), 0)
	badJPEG := jpeg[:len(jpeg)-2]
	badWebP := webp[:12]
	reservedWebP := append([]byte(nil), webpEXIF...)
	reservedWebP[20] = 0x09
	lateExtendedWebP := append(append([]byte(nil), webp...), webpEXIF[12:30]...)
	binary.LittleEndian.PutUint32(lateExtendedWebP[4:8], uint32(len(lateExtendedWebP)-8))
	for _, testCase := range []struct {
		name string
		data []byte
		mime string
	}{
		{name: "png crc", data: brokenCRC, mime: "image/png"},
		{name: "png missing idat", data: missingIDAT, mime: "image/png"},
		{name: "png trailing", data: trailing, mime: "image/png"},
		{name: "jpeg missing eoi", data: badJPEG, mime: "image/jpeg"},
		{name: "empty webp", data: badWebP, mime: "image/webp"},
		{name: "webp reserved flag", data: reservedWebP, mime: "image/webp"},
		{name: "webp late extended", data: lateExtendedWebP, mime: "image/webp"},
		{name: "wrong mime", data: png, mime: "image/jpeg"},
	} {
		if validIdleAssetBytes(testCase.data, testCase.mime) {
			t.Errorf("malformed %s fixture was accepted", testCase.name)
		}
	}
}

func newAssetRuntime(t *testing.T, origin string, client *http.Client) *SwayIdleRuntime {
	t.Helper()
	runtime, err := NewSwayIdleRuntime(IdleRuntimeOptions{StateDir: t.TempDir(), SwayidleBinary: "/usr/bin/swayidle", InstanceURL: origin, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestCacheIdleAssetsDownloadsVerifiedBytesToPrivateCache(t *testing.T) {
	data := testAssetPNG(t)
	desired, digest := idleCacheTestDesired(t, data, "image/png")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/idle-assets/asset-id/"+digest {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "image/png")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(data)
	}))
	defer server.Close()
	runtime := newAssetRuntime(t, server.URL, server.Client())
	directory := t.TempDir()
	if err := runtime.cacheIdleAssets(context.Background(), directory, &desired); err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(directory, "assets")
	if mode, err := os.Stat(assets); err != nil || mode.Mode().Perm() != 0o700 {
		t.Fatalf("asset directory mode = %v, err=%v", mode, err)
	}
	file := filepath.Join(assets, digest+".png")
	if mode, err := os.Stat(file); err != nil || mode.Mode().Perm() != 0o600 {
		t.Fatalf("asset file mode = %v, err=%v", mode, err)
	}
	if got, err := os.ReadFile(file); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("cached bytes differ: len=%d err=%v", len(got), err)
	}
}

func TestCacheIdleAssetsAllowsSameOriginRedirect(t *testing.T) {
	data := testAssetPNG(t)
	desired, digest := idleCacheTestDesired(t, data, "image/png")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery == "" {
			writer.Header().Set("Location", request.URL.Path+"?same-origin=1")
			writer.WriteHeader(http.StatusFound)
			return
		}
		if request.URL.Path != "/v1/idle-assets/asset-id/"+digest {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "image/png")
		_, _ = writer.Write(data)
	}))
	defer server.Close()
	runtime := newAssetRuntime(t, server.URL, server.Client())
	directory := t.TempDir()
	if err := runtime.cacheIdleAssets(context.Background(), directory, &desired); err != nil {
		t.Fatal(err)
	}
	assets, err := os.Stat(filepath.Join(directory, "assets"))
	if err != nil || assets.Mode().Perm() != 0o700 {
		t.Fatalf("redirect asset directory mode = %v, err=%v", assets, err)
	}
	file, err := os.Stat(filepath.Join(directory, "assets", digest+".png"))
	if err != nil || file.Mode().Perm() != 0o600 {
		t.Fatalf("redirect asset file mode = %v, err=%v", file, err)
	}
}

func TestCacheIdleAssetsBoundsSameOriginRedirects(t *testing.T) {
	data := testAssetPNG(t)
	desired, digest := idleCacheTestDesired(t, data, "image/png")
	redirects := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if redirects < 11 {
			redirects++
			writer.Header().Set("Location", request.URL.Path+fmt.Sprintf("?redirect=%d", redirects))
			writer.WriteHeader(http.StatusFound)
			return
		}
		writer.Header().Set("Content-Type", "image/png")
		_, _ = writer.Write(data)
	}))
	defer server.Close()
	runtime := newAssetRuntime(t, server.URL, server.Client())
	directory := t.TempDir()
	if err := runtime.cacheIdleAssets(context.Background(), directory, &desired); err == nil {
		t.Fatal("redirect loop was accepted")
	}
	if _, err := os.Stat(filepath.Join(directory, "assets", digest+".png")); !os.IsNotExist(err) {
		t.Fatalf("redirect loop activated a final cache file: %v", err)
	}
}

type idleRoundTripFunc func(*http.Request) (*http.Response, error)

func (function idleRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type countingIdleAssetReader struct {
	io.Reader
	bytesRead int
}

func (reader *countingIdleAssetReader) Read(data []byte) (int, error) {
	n, err := reader.Reader.Read(data)
	reader.bytesRead += n
	return n, err
}

func TestCacheIdleAssetsRejectsRedirectsBadResponsesAndCorruptContent(t *testing.T) {
	data := testAssetPNG(t)
	for _, testCase := range []struct{ name, wantError string }{
		{"cross-origin redirect", "redirect was not same-origin"},
		{"non-200", "response was not same-origin"},
		{"empty body", "metadata mismatch"},
		{"streamed oversize", "metadata mismatch"},
		{"MIME mismatch", "metadata mismatch"},
		{"SHA mismatch", "hash mismatch"},
		{"malformed container", "magic mismatch"},
		{"transfer failure", "synthetic transfer failure"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			desired, digest := idleCacheTestDesired(t, data, "image/png")
			body := append([]byte(nil), data...)
			mime, status := "image/png", http.StatusOK
			switch testCase.name {
			case "non-200":
				status = http.StatusNotFound
			case "MIME mismatch":
				mime = "image/jpeg"
			case "SHA mismatch":
				body[0] ^= 0xff
			case "malformed container":
				body[29] ^= 0xff
				// Authenticate the malformed bytes so container validation is reached.
				desired, digest = idleCacheTestDesired(t, body, "image/png")
			}
			var reader *countingIdleAssetReader
			var redirected atomic.Int32
			var client *http.Client
			origin := "https://asset.invalid"
			switch testCase.name {
			case "empty body", "transfer failure", "streamed oversize":
				client = &http.Client{Transport: idleRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					if testCase.name == "transfer failure" {
						return nil, errors.New("synthetic transfer failure")
					}
					response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{mime}}, Request: request}
					if testCase.name == "streamed oversize" {
						reader = &countingIdleAssetReader{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), 2*1024*1024+64))}
						response.Body, response.ContentLength = io.NopCloser(reader), -1
					}
					return response, nil
				})}
			case "cross-origin redirect":
				target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					redirected.Add(1)
					writer.Header().Set("Content-Type", mime)
					_, _ = writer.Write(body)
				}))
				defer target.Close()
				server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					writer.Header().Set("Location", target.URL+request.URL.Path)
					writer.WriteHeader(http.StatusFound)
				}))
				defer server.Close()
				origin, client = server.URL, target.Client()
			default:
				server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					writer.Header().Set("Content-Type", mime)
					writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
					writer.WriteHeader(status)
					_, _ = writer.Write(body)
				}))
				defer server.Close()
				origin, client = server.URL, server.Client()
			}
			runtime := newAssetRuntime(t, origin, client)
			directory := t.TempDir()
			if err := runtime.cacheIdleAssets(context.Background(), directory, &desired); err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("asset response error = %v, want %q", err, testCase.wantError)
			}
			if redirected.Load() != 0 {
				t.Fatal("cross-origin redirect was contacted")
			}
			if testCase.name == "streamed oversize" && (reader == nil || reader.bytesRead != 2*1024*1024+1) {
				t.Fatalf("download did not stop at the byte limit: %+v", reader)
			}
			if _, err := os.Stat(filepath.Join(directory, "assets", digest+".png")); !os.IsNotExist(err) {
				t.Fatalf("invalid response activated a final cache file: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(directory, "assets", ".asset-*.tmp"))
			if err != nil || len(matches) != 0 {
				t.Fatalf("invalid response left temporary cache files: %v %v", matches, err)
			}
		})
	}
}

func TestSwayIdleRuntimeUsesBlockingIsolatedHelper(t *testing.T) {
	runner := &fakeIdleRunner{}
	stateDir := t.TempDir()
	environment := []string{"XDG_RUNTIME_DIR=/run/user/967", "WAYLAND_DISPLAY=wayland-1", "SWAYSOCK=/run/user/967/sway-ipc.sock"}
	runtime, err := NewSwayIdleRuntime(IdleRuntimeOptions{StateDir: stateDir, SwayidleBinary: "/usr/bin/swayidle", AgentBinary: "/usr/local/bin/novakiosk-agent", ChromiumBinary: "/usr/bin/chromium", CommandRunner: runner, environment: environment})
	if err != nil {
		t.Fatal(err)
	}
	desired := testIdleDesired(t)
	if err := runtime.Apply(context.Background(), &desired); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 1 {
		t.Fatalf("starts = %#v", runner.starts)
	}
	call := runner.starts[0]
	if call.name != "/usr/bin/swayidle" || len(call.args) != 4 || call.args[0] != "-w" || call.args[1] != "timeout" || call.args[2] != "60" {
		t.Fatalf("swayidle argv = %#v", call)
	}
	if !strings.Contains(call.args[3], "'/usr/local/bin/novakiosk-agent' idle-surface --state-dir '") || !strings.Contains(call.args[3], " --chromium '/usr/bin/chromium'") {
		t.Fatalf("blocking helper command = %q", call.args[3])
	}
	for _, forbidden := range []string{"resume", "swaymsg", "scratchpad", "fullscreen", "Presentation", "--remote-debugging-port"} {
		if strings.Contains(call.args[3], forbidden) {
			t.Fatalf("helper command contains forbidden %q: %q", forbidden, call.args[3])
		}
	}
	if !reflect.DeepEqual(call.environment, environment) {
		t.Fatalf("idle environment = %#v, want %#v", call.environment, environment)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "idle", "idle.html")); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Apply(context.Background(), &desired); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 1 {
		t.Fatalf("same hash was not idempotent: %#v", runner.starts)
	}
	desired.Texts[0].Text = "Updated"
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	if err := runtime.Apply(context.Background(), &desired); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 2 || !runner.processes[0].killed || !runner.processes[0].waited {
		t.Fatalf("content revision did not replace only helper group: starts=%#v processes=%#v", runner.starts, runner.processes)
	}
	desired.TimeoutSeconds = 90
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	if err := runtime.Apply(context.Background(), &desired); err != nil {
		t.Fatal(err)
	}
	if len(runner.starts) != 3 || !runner.processes[1].killed || !runner.processes[1].waited {
		t.Fatalf("timeout revision did not replace helper group: starts=%#v processes=%#v", runner.starts, runner.processes)
	}
	if err := runtime.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !runner.processes[2].killed || !runner.processes[2].waited {
		t.Fatal("nil desired did not stop the idle helper group")
	}
}

func TestDisposableIdleProfileCleanupUnlinksOnlyChildSymlinks(t *testing.T) {
	stateDir := t.TempDir()
	profile := filepath.Join(stateDir, idleProfileName)
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("must survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(profile, "SingletonSocket")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "Preferences"), []byte("disposable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeDisposableIdleProfile(profile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(profile); !os.IsNotExist(err) {
		t.Fatalf("idle profile remains after cleanup: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "must survive" {
		t.Fatalf("symlink target was changed or removed: %q, %v", data, err)
	}
}

func TestIdleSurfacePathsRejectSymlinkedStateAndDocument(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(stateDir, idleDirectoryName)); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdleDirectory(filepath.Join(stateDir, idleDirectoryName)); err == nil {
		t.Fatal("symlinked idle directory was accepted")
	}
	if err := os.Remove(filepath.Join(stateDir, idleDirectoryName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stateDir, idleDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.html")
	if err := os.WriteFile(outside, []byte("not local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(stateDir, idleDirectoryName, idleDocumentName)); err != nil {
		t.Fatal(err)
	}
	if err := validateIdleDocumentFile(filepath.Join(stateDir, idleDirectoryName, idleDocumentName)); err == nil {
		t.Fatal("symlinked idle document was accepted")
	}
}

type recordingIdleRuntime struct {
	calls int
	err   error
}

func (runtime *recordingIdleRuntime) Apply(_ context.Context, _ *IdleDesired) error {
	runtime.calls++
	return runtime.err
}
func (runtime *recordingIdleRuntime) Close() error { return nil }

func TestAppliedIdleStateStillEnsuresFreshRuntime(t *testing.T) {
	desired := testIdleDesired(t)
	state := State{LastIdleScreenID: desired.IdleScreenID, LastIdleRevisionID: desired.RevisionID, LastIdlePayloadHash: desired.PayloadHash, LastIdleAckResult: "applied", LastIdleAckAccepted: true}
	runtime := &recordingIdleRuntime{}
	client := Client{StateDir: t.TempDir()}
	if err := client.applyIdleAndAcknowledge(context.Background(), &state, Identity{}, nil, DesiredSnapshot{Idle: &desired}, runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 1 {
		t.Fatalf("runtime Apply calls = %d, want 1", runtime.calls)
	}
}

func TestIdleErrorStageIsBounded(t *testing.T) {
	for _, test := range []struct{ message, want string }{
		{"idle graphical environment unavailable: secret", "graphical-environment"},
		{"idle Sway environment unavailable: secret", "sway-environment"},
		{"start idle Chromium: secret", "chromium-start"},
		{"navigate idle document: secret", "chromium-navigation"},
		{"wait for idle input: secret", "input-wait"},
		{"clean idle Chromium profile: secret", "profile-cleanup"},
		{"idle inactivity supervisor unavailable: secret", "swayidle-start"},
	} {
		if got := idleErrorStage(errors.New(test.message)); got != test.want {
			t.Fatalf("idleErrorStage(%q) = %q, want %q", test.message, got, test.want)
		}
	}
}

func TestIdleTextPreservesExplicitLinesWithoutWrappingAtCanvasEdge(t *testing.T) {
	desired := testIdleDesired(t)
	desired.Texts[0].Text = strings.Repeat("Long heading ", 20) + "\nExplicit second line"
	desired.Texts[0].XPercent = 95
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	data, err := IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	markup := string(data)
	for _, want := range []string{"width:max-content;max-width:none", "white-space:pre;overflow-wrap:normal", desired.Texts[0].Text, "left:95%"} {
		if !strings.Contains(markup, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestIdleProgressiveJPEGMultipleScans(t *testing.T) {
	// Synthetic one-pixel grayscale image, generated with libjpeg's
	// jpeg_simple_progression from a single pixel with value 128.
	data, err := base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wgALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAAAAF//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABBQJ//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAGPwJ//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPyF//9oACAEBAAAAEH//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAE/EH//2Q==")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jpeg.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("invalid test JPEG: %v", err)
	}
	if !validIdleJPEG(data) {
		t.Fatal("valid progressive JPEG rejected")
	}
	for _, bad := range [][]byte{data[:len(data)-2], append(append([]byte(nil), data...), 0), data[:len(data)/2]} {
		if validIdleJPEG(bad) {
			t.Fatal("truncated or trailing progressive JPEG accepted")
		}
	}
}

func TestIdleCommandRunnerNaturalExitKillsDescendants(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child.pid")
	command := "sleep 30 & child=$!; printf '%s' \"$child\" > " + idleShellQuote(marker) + "; exit 0"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	process, err := (execIdleCommandRunner{}).Start(ctx, "/bin/sh", []string{"-c", command}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	// On a failing baseline, explicitly clean the still-owned group.
	defer func() { _ = process.Kill(); _ = process.Wait() }()
	if err := process.Wait(); err != nil {
		t.Fatalf("natural wait result changed: %v", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid child PID %q", data)
	}
	runtime := &SwayIdleRuntime{swayidle: process}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		// A zombie has terminated and cannot keep idle surfaces alive; its reaping
		// belongs to the host's parent after the controlled shell exits.
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil && strings.Contains(string(stat), ") Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child %d survived normal parent Wait and runtime Close", pid)
}

func TestIdleJPEGAllowsZeroComponentIdentifier(t *testing.T) {
	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, image.NewGray(image.Rect(0, 0, 1, 1)), nil); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	sof, sos := false, false
	for offset := 2; offset < len(data); {
		marker, next, ok := idleJPEGMarker(data, offset)
		if !ok {
			t.Fatal("generated JPEG marker invalid")
		}
		length := int(binary.BigEndian.Uint16(data[next : next+2]))
		if marker == 0xc0 {
			data[next+8] = 0
			sof = true
		}
		if marker == 0xda {
			data[next+3] = 0
			sos = true
			break
		}
		offset = next + length
	}
	if !sof || !sos {
		t.Fatal("generated grayscale JPEG lacks frame/scan")
	}
	if _, err := jpeg.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("zero-ID JPEG invalid: %v", err)
	}
	if !validIdleJPEG(data) {
		t.Fatal("valid declared component zero rejected")
	}
}

type assetCleanupRunner struct {
	fakeIdleRunner
	failStart bool
}

func (runner *assetCleanupRunner) Start(ctx context.Context, name string, args, environment []string) (idleProcess, error) {
	if runner.failStart {
		return nil, errors.New("start failed")
	}
	return runner.fakeIdleRunner.Start(ctx, name, args, environment)
}

func assetCleanupRuntime(t *testing.T, body *[]byte, runner idleCommandRunner) *SwayIdleRuntime {
	t.Helper()
	client := &http.Client{Transport: idleRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"image/png"}}, Body: io.NopCloser(bytes.NewReader(*body)), ContentLength: int64(len(*body)), Request: request}, nil
	})}
	runtime, err := NewSwayIdleRuntime(IdleRuntimeOptions{StateDir: t.TempDir(), SwayidleBinary: "/usr/bin/swayidle", AgentBinary: "/usr/local/bin/novakiosk-agent", InstanceURL: "https://control.example", HTTPClient: client, CommandRunner: runner, environment: []string{"XDG_RUNTIME_DIR=/run/user/967", "WAYLAND_DISPLAY=wayland-1", "SWAYSOCK=/run/user/967/sway-ipc.sock"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func TestIdleAssetCacheRetiresRotatedAndUnassignedFiles(t *testing.T) {
	var body []byte
	runtime := assetCleanupRuntime(t, &body, &fakeIdleRunner{})
	assets := filepath.Join(runtime.options.StateDir, "idle", "assets")
	for index := range 12 {
		img := image.NewRGBA(image.Rect(0, 0, 1, 1))
		img.Set(0, 0, color.RGBA{R: uint8(index), A: 255})
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, img); err != nil {
			t.Fatal(err)
		}
		body = encoded.Bytes()
		desired, digest := idleCacheTestDesired(t, body, "image/png")
		if err := runtime.Apply(context.Background(), &desired); err != nil {
			t.Fatal(err)
		}
		files, err := os.ReadDir(assets)
		if err != nil || len(files) != 1 || files[0].Name() != digest+".png" {
			t.Errorf("old assets retained at revision %d: %v %v", index, files, err)
		}
	}
	if err := runtime.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(assets)
	if err != nil || len(files) != 0 {
		t.Fatalf("unassignment retained assets: %v %v", files, err)
	}
}

func TestIdleAssetFailedUpdatePreservesPreviousAssets(t *testing.T) {
	body := testAssetPNG(t)
	runner := &assetCleanupRunner{}
	runtime := assetCleanupRuntime(t, &body, runner)
	old, digest := idleCacheTestDesired(t, body, "image/png")
	if err := runtime.Apply(context.Background(), &old); err != nil {
		t.Fatal(err)
	}
	next := old
	next.Logos = nil
	next.PayloadHash = IdleScreenPayloadHash(next)
	runner.failStart = true
	if err := runtime.Apply(context.Background(), &next); err == nil {
		t.Fatal("failed start unexpectedly succeeded")
	}
	path := filepath.Join(runtime.options.StateDir, "idle", "assets", digest+".png")
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, body) {
		t.Fatal("failed update retired previous asset")
	}
	runner.failStart = false
	if err := runtime.Apply(context.Background(), &next); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("successful no-logo update retained old asset")
	}
}

func TestIdleAssetCleanupRetriesAndDoesNotFollowSymlinks(t *testing.T) {
	body := testAssetPNG(t)
	runner := &fakeIdleRunner{}
	runtime := assetCleanupRuntime(t, &body, runner)
	desired, _ := idleCacheTestDesired(t, body, "image/png")
	if err := runtime.Apply(context.Background(), &desired); err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(runtime.options.StateDir, "idle", "assets")
	partial := filepath.Join(assets, ".asset-interrupted.tmp")
	if err := os.WriteFile(partial, []byte("partial download"), 0600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(assets, "notes")
	if err := os.WriteFile(unknown, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(assets, strings.Repeat("a", 64)+".png")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Apply(context.Background(), &desired); err == nil {
		t.Fatal("same-hash apply hid cleanup failure")
	}
	if err := os.Remove(filepath.Join(blocked, "keep")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(assets, strings.Repeat("b", 64)+".png")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Apply(context.Background(), &desired); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("stale symlink was not unlinked")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "preserve" {
		t.Fatal("asset cleanup followed symlink")
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatal("interrupted download retained")
	}
	if len(runner.starts) != 1 {
		t.Fatal("cleanup retry restarted active runtime")
	}
	if err := os.Rename(assets, assets+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), assets); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Apply(context.Background(), &desired); err == nil {
		t.Fatal("symlinked asset directory accepted")
	}
	if err := os.Remove(assets); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(assets+".saved", assets); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Apply(context.Background(), nil); err == nil {
		t.Fatal("unassignment hid cleanup failure")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(assets)
	if err != nil || len(files) != 1 || files[0].Name() != "notes" {
		t.Fatalf("unassignment failed to preserve unrelated file: %v %v", files, err)
	}
}

type lifecycleIdleRunner struct {
	fakeIdleRunner
	ctx context.Context
}

func (runner *lifecycleIdleRunner) Start(ctx context.Context, name string, args, env []string) (idleProcess, error) {
	runner.ctx = ctx
	return runner.fakeIdleRunner.Start(ctx, name, args, env)
}
func TestIdleSupervisorOutlivesApplyLease(t *testing.T) {
	lifetime, disconnect := context.WithCancel(context.Background())
	defer disconnect()
	operation, complete := context.WithCancel(lifetime)
	runner := &lifecycleIdleRunner{}
	runtime, err := NewSwayIdleRuntime(IdleRuntimeOptions{StateDir: t.TempDir(), LifecycleContext: lifetime, CommandRunner: runner, environment: []string{"XDG_RUNTIME_DIR=/run/user/967", "WAYLAND_DISPLAY=wayland-1", "SWAYSOCK=/run/user/967/sway-ipc.sock"}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	desired := testIdleDesired(t)
	if err := runtime.Apply(operation, &desired); err != nil {
		t.Fatal(err)
	}
	complete()
	if runner.ctx.Err() != nil {
		t.Fatal("successful Apply lease killed persistent supervisor")
	}
	disconnect()
	if runner.ctx.Err() == nil {
		t.Fatal("disconnect did not cancel persistent supervisor")
	}
}
