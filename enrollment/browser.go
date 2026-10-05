package enrollment

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Browser owns one top-level page for the lifetime of a Run call. Navigate
// must reuse that page; it is deliberately narrower than a general browser
// automation channel. Owned child implementations expose Done() <-chan struct{}
// so Run can invalidate applied content when the process exits.
type Browser interface {
	Navigate(context.Context, string) (string, error)
	Reload(context.Context) (string, error)
	SetZoom(context.Context, int) (string, int, error)
	Close() error
}

type BrowserFactory func(context.Context, string) (Browser, error)

type ChromiumOptions struct {
	// LifecycleContext owns Chromium independently of bounded startup work.
	LifecycleContext        context.Context
	Binary                  string
	UserDataDir             string
	ExtraArgs               []string
	Kiosk                   bool
	KioskPrinting           bool
	KioskConfigured         bool
	RequireGraphicalSession bool
	Environment             []string
	// InitialURL is used only by the internal disposable idle surface. The
	// managed presentation browser always starts at about:blank and navigates
	// through Browser.Navigate.
	InitialURL string
	// These narrow filesystem seams are intentionally unexported: production
	// always uses os.Lstat, while package tests can model ownership/socket
	// boundaries without opening a real compositor socket.
	runtimeDirInfo    func(string) (os.FileInfo, error)
	waylandSocketInfo func(string) (os.FileInfo, error)
}

type chromiumBrowser struct {
	cmd      *exec.Cmd
	command  *os.File
	response *os.File
	reader   *bufio.Reader
	writeMu  sync.Mutex
	readMu   sync.Mutex
	id       int64
	session  string
	targetID string
	closed   bool
	done     chan struct{}
}

const maxChromiumPipeMessage = 16 * 1024 * 1024

func readChromiumPipeMessage(reader *bufio.Reader) ([]byte, error) {
	message := make([]byte, 0, 64*1024)
	for {
		chunk, err := reader.ReadSlice(0)
		if len(message)+len(chunk) > maxChromiumPipeMessage+1 {
			return nil, fmt.Errorf("Chromium response is too large")
		}
		message = append(message, chunk...)
		if len(message) > 0 && message[len(message)-1] == 0 {
			return message[:len(message)-1], nil
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if len(message) > maxChromiumPipeMessage {
				return nil, fmt.Errorf("Chromium response is too large")
			}
			return nil, fmt.Errorf("read Chromium response: %w", err)
		}
	}
}

type cdpEnvelope struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func NewChromiumBrowser(ctx context.Context, options ChromiumOptions) (Browser, error) {
	if options.Binary == "" {
		options.Binary = resolveChromiumBinary()
	}
	if options.UserDataDir == "" {
		return nil, fmt.Errorf("persistent Chromium user-data directory is required")
	}
	for _, arg := range options.ExtraArgs {
		if strings.HasPrefix(arg, "--remote-debugging-port") || strings.HasPrefix(arg, "--remote-debugging-address") {
			return nil, fmt.Errorf("network Chromium debugging is not permitted; use --remote-debugging-pipe")
		}
	}
	if options.InitialURL != "" {
		parsed, parseErr := url.Parse(options.InitialURL)
		if parseErr != nil || parsed.Scheme != "file" || parsed.Host != "" || !filepath.IsAbs(parsed.Path) || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("Chromium initial URL is invalid")
		}
	}
	if err := ensureChromiumUserDataDir(options.UserDataDir); err != nil {
		return nil, err
	}
	commandRead, commandWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create Chromium command pipe: %w", err)
	}
	responseRead, responseWrite, err := os.Pipe()
	if err != nil {
		_ = commandRead.Close()
		_ = commandWrite.Close()
		return nil, fmt.Errorf("create Chromium response pipe: %w", err)
	}
	args := chromiumArguments(options)
	lifetime := ctx
	if options.LifecycleContext != nil {
		lifetime = options.LifecycleContext
	}
	command := exec.CommandContext(lifetime, options.Binary, args...)
	environment, envErr := browserEnvironment(options)
	if envErr != nil {
		_ = commandRead.Close()
		_ = commandWrite.Close()
		_ = responseRead.Close()
		_ = responseWrite.Close()
		return nil, envErr
	}
	command.Env = environment
	// Chromium reads commands from fd 3 and writes responses to fd 4 when
	// --remote-debugging-pipe is enabled. ExtraFiles maps to those descriptors.
	command.ExtraFiles = []*os.File{commandRead, responseWrite}
	if err := command.Start(); err != nil {
		_ = commandRead.Close()
		_ = commandWrite.Close()
		_ = responseRead.Close()
		_ = responseWrite.Close()
		return nil, fmt.Errorf("start Chromium: %w", err)
	}
	_ = commandRead.Close()
	_ = responseWrite.Close()
	browser := &chromiumBrowser{
		cmd: command, command: commandWrite, response: responseRead,
		reader: bufio.NewReaderSize(responseRead, 64*1024),
		id:     1,
		done:   make(chan struct{}),
	}
	go func() {
		_ = command.Wait()
		close(browser.done)
	}()
	if _, err := browser.call(ctx, "Browser.getVersion", nil, ""); err != nil {
		_ = browser.Close()
		return nil, fmt.Errorf("connect Chromium debugging pipe: %w", err)
	}
	targetsRaw, err := browser.call(ctx, "Target.getTargets", map[string]any{}, "")
	if err != nil {
		_ = browser.Close()
		return nil, err
	}
	var targets struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(targetsRaw, &targets); err != nil {
		_ = browser.Close()
		return nil, fmt.Errorf("decode Chromium targets: %w", err)
	}
	for _, target := range targets.TargetInfos {
		if target.Type == "page" {
			browser.targetID = target.TargetID
			break
		}
	}
	if browser.targetID == "" {
		created, createErr := browser.call(ctx, "Target.createTarget", map[string]any{"url": "about:blank"}, "")
		if createErr != nil {
			_ = browser.Close()
			return nil, createErr
		}
		var target struct {
			TargetID string `json:"targetId"`
		}
		if err := json.Unmarshal(created, &target); err != nil || target.TargetID == "" {
			_ = browser.Close()
			return nil, fmt.Errorf("Chromium did not create a page target")
		}
		browser.targetID = target.TargetID
	}
	attached, err := browser.call(ctx, "Target.attachToTarget", map[string]any{"targetId": browser.targetID, "flatten": true}, "")
	if err != nil {
		_ = browser.Close()
		return nil, err
	}
	var attachedTarget struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(attached, &attachedTarget); err != nil || attachedTarget.SessionID == "" {
		_ = browser.Close()
		return nil, fmt.Errorf("Chromium did not attach a page target")
	}
	browser.session = attachedTarget.SessionID
	if _, err := browser.call(ctx, "Page.enable", map[string]any{}, browser.session); err != nil {
		_ = browser.Close()
		return nil, err
	}
	if _, err := browser.call(ctx, "Runtime.enable", map[string]any{}, browser.session); err != nil {
		_ = browser.Close()
		return nil, err
	}
	return browser, nil
}

func chromiumArguments(options ChromiumOptions) []string {
	args := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=" + options.UserDataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
	}
	if !options.KioskConfigured || options.Kiosk {
		args = append(args, "--kiosk")
	}
	if options.KioskConfigured && options.KioskPrinting {
		args = append(args, "--kiosk-printing")
	}
	if options.RequireGraphicalSession {
		args = append(args, "--ozone-platform=wayland")
	}
	args = append(args, options.ExtraArgs...)
	initialURL := options.InitialURL
	if initialURL == "" {
		initialURL = "about:blank"
	}
	args = append(args, initialURL)
	return args
}

func ensureChromiumUserDataDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create Chromium user-data directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect Chromium user-data directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("Chromium user-data path must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("Chromium user-data directory must have mode 0700")
	}
	return nil
}

func (browser *chromiumBrowser) call(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, error) {
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	browser.writeMu.Lock()
	id := browser.id
	browser.id++
	browser.writeMu.Unlock()
	message := cdpEnvelope{ID: id, Method: method, SessionID: sessionID}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		message.Params = encoded
	}
	data, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	browser.writeMu.Lock()
	defer browser.writeMu.Unlock()
	// Chromium's DevToolsPipeHandler uses ASCIIZ framing: one JSON message
	// terminated by NUL, rather than the length-prefixed framing used by some
	// CDP transports.
	frame := append(data, 0)
	_ = browser.command.SetWriteDeadline(deadline)
	if _, err := browser.command.Write(frame); err != nil {
		return nil, fmt.Errorf("write Chromium command: %w", err)
	}
	browser.readMu.Lock()
	defer browser.readMu.Unlock()
	for {
		_ = browser.response.SetReadDeadline(deadline)
		payload, err := readChromiumPipeMessage(browser.reader)
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 || len(payload) > maxChromiumPipeMessage {
			return nil, fmt.Errorf("Chromium response is too large")
		}
		var response cdpEnvelope
		if err := json.Unmarshal(payload, &response); err != nil {
			return nil, fmt.Errorf("decode Chromium response: %w", err)
		}
		if response.ID != id {
			continue // unsolicited page event
		}
		if response.Error != nil {
			return nil, errors.New(response.Error.Message)
		}
		return response.Result, nil
	}
}

func (browser *chromiumBrowser) Navigate(ctx context.Context, target string) (string, error) {
	normalized, err := CanonicalPresentationURL(target)
	if err != nil {
		return "", err
	}
	if browser == nil || browser.closed {
		return "", errors.New("Chromium browser is closed")
	}
	return browser.navigateAndWait(ctx, normalized, func(observed string) bool {
		canonical, canonicalErr := CanonicalPresentationURL(observed)
		return canonicalErr == nil && canonical == normalized
	})
}

func (browser *chromiumBrowser) currentURL(ctx context.Context) (string, error) {
	result, err := browser.call(ctx, "Runtime.evaluate", map[string]any{"expression": "window.location.href", "returnByValue": true}, browser.session)
	if err != nil {
		return "", err
	}
	var value struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result, &value); err != nil || value.Result.Value == "" {
		return "", errors.New("Chromium URL observation is invalid")
	}
	return CanonicalPresentationURL(value.Result.Value)
}

func (browser *chromiumBrowser) Reload(ctx context.Context) (string, error) {
	if browser == nil || browser.closed {
		return "", errors.New("Chromium browser is closed")
	}
	if _, err := browser.call(ctx, "Page.reload", map[string]any{"ignoreCache": false}, browser.session); err != nil {
		return "", err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if observed, err := browser.currentURL(ctx); err == nil {
			return observed, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", errors.New("Chromium reload observation timed out")
}

func (browser *chromiumBrowser) SetZoom(ctx context.Context, percent int) (string, int, error) {
	if !BrowserZoomAllowlist[percent] {
		return "", 0, errors.New("browser zoom is not allowed")
	}
	if browser == nil || browser.closed {
		return "", 0, errors.New("Chromium browser is closed")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	observed, scale, err := browser.zoomMetrics(ctx)
	if err != nil {
		return "", 0, err
	}
	// Retire any pinch scaling left by older Agent versions before native zoom.
	if math.Abs(scale-1) > 0.001 {
		if _, err = browser.call(ctx, "Emulation.setPageScaleFactor", map[string]any{"pageScaleFactor": 1}, browser.session); err != nil {
			return "", 0, err
		}
		observed, err = browser.waitForZoom(ctx, func(int) bool { return true })
		if err != nil {
			return "", 0, err
		}
	}
	if observed != percent && observed != 100 {
		if err = browser.zoomKey(ctx, "0", "Digit0", 48); err != nil {
			return "", 0, err
		}
		observed, err = browser.waitForZoom(ctx, func(value int) bool { return value == 100 })
		if err != nil {
			return "", 0, err
		}
	}
	key, code, virtualKey := "+", "Equal", 187
	if percent < 100 {
		key, code, virtualKey = "-", "Minus", 189
	}
	for step := 0; observed != percent && step < 5; step++ {
		previous := observed
		if err = browser.zoomKey(ctx, key, code, virtualKey); err != nil {
			return "", 0, err
		}
		observed, err = browser.waitForZoom(ctx, func(value int) bool { return value != previous })
		if err != nil {
			return "", 0, err
		}
		if percent < 100 && (observed >= previous || observed < percent) || percent > 100 && (observed <= previous || observed > percent) {
			return "", 0, errors.New("Chromium zoom changed unexpectedly")
		}
	}
	if observed != percent {
		return "", 0, errors.New("Chromium zoom target was not reached")
	}
	currentURL, err := browser.currentURL(ctx)
	if err != nil {
		return "", 0, err
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	return currentURL, observed, nil
}

func (browser *chromiumBrowser) zoomMetrics(ctx context.Context) (int, float64, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	raw, err := browser.call(ctx, "Page.getLayoutMetrics", nil, browser.session)
	if err != nil {
		return 0, 0, err
	}
	var metrics struct {
		Viewport struct {
			Zoom  float64 `json:"zoom"`
			Scale float64 `json:"scale"`
		} `json:"cssVisualViewport"`
	}
	if json.Unmarshal(raw, &metrics) != nil || metrics.Viewport.Zoom <= 0 || metrics.Viewport.Scale <= 0 || math.IsInf(metrics.Viewport.Zoom, 0) || math.IsInf(metrics.Viewport.Scale, 0) {
		return 0, 0, errors.New("Chromium zoom metrics are invalid")
	}
	return int(math.Round(metrics.Viewport.Zoom * 100)), metrics.Viewport.Scale, nil
}

func (browser *chromiumBrowser) waitForZoom(ctx context.Context, reached func(int) bool) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		zoom, scale, err := browser.zoomMetrics(ctx)
		if err != nil {
			return 0, err
		}
		if math.Abs(scale-1) <= 0.001 && reached(zoom) {
			return zoom, nil
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
}

func (browser *chromiumBrowser) zoomKey(ctx context.Context, key, code string, virtualKey int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	params := map[string]any{"type": "rawKeyDown", "key": key, "code": code, "windowsVirtualKeyCode": virtualKey, "nativeVirtualKeyCode": virtualKey, "modifiers": 2}
	_, downErr := browser.call(ctx, "Input.dispatchKeyEvent", params, browser.session)
	// Always release the dispatched key, including after cancellation/error.
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	params["type"] = "keyUp"
	_, upErr := browser.call(releaseCtx, "Input.dispatchKeyEvent", params, browser.session)
	return errors.Join(downErr, upErr, ctx.Err())
}

func (browser *chromiumBrowser) navigateAndWait(ctx context.Context, target string, reached func(string) bool) (string, error) {
	if browser == nil || browser.closed {
		return "", errors.New("Chromium browser is closed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	result, err := browser.call(ctx, "Page.navigate", map[string]any{"url": target}, browser.session)
	if err != nil {
		return "", err
	}
	var navigation struct {
		ErrorText  string `json:"errorText"`
		IsDownload bool   `json:"isDownload"`
	}
	if json.Unmarshal(result, &navigation) != nil || navigation.ErrorText != "" || navigation.IsDownload {
		return "", errors.New("Chromium navigation failed")
	}
	// Polling location.href avoids treating an early Page.navigate response as
	// applied; it also works for pages that do not emit a load event.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		result, callErr := browser.call(ctx, "Runtime.evaluate", map[string]any{
			"expression":    "window.location.href",
			"returnByValue": true,
		}, browser.session)
		if callErr == nil {
			var value struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			if json.Unmarshal(result, &value) == nil {
				if reached(value.Result.Value) {
					return value.Result.Value, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("Chromium navigation did not reach requested URL")
}

func (browser *chromiumBrowser) NavigateIdleFile(ctx context.Context, path string) (string, error) {
	if err := validateIdleDocumentPath(path); err != nil {
		return "", err
	}
	target := (&url.URL{Scheme: "file", Path: path}).String()
	return browser.navigateAndWait(ctx, target, func(observed string) bool {
		return observed == target
	})
}

const idleInputMarkerExpression = "Boolean(window.__novaIdleInputSeen === true)"

func (browser *chromiumBrowser) WaitForIdleInput(ctx context.Context) error {
	if browser == nil || browser.closed {
		return errors.New("Chromium browser is closed")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := browser.call(ctx, "Runtime.evaluate", map[string]any{
			"expression":    idleInputMarkerExpression,
			"returnByValue": true,
		}, browser.session)
		if err != nil {
			return fmt.Errorf("read idle input marker: %w", err)
		}
		var evaluated struct {
			Result struct {
				Value bool `json:"value"`
			} `json:"result"`
		}
		if json.Unmarshal(result, &evaluated) == nil && evaluated.Result.Value {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Done closes when the owned child has exited and been reaped.
func (browser *chromiumBrowser) Done() <-chan struct{} { return browser.done }

func (browser *chromiumBrowser) Close() error {
	if browser == nil || browser.closed {
		return nil
	}
	browser.closed = true
	_ = browser.command.Close()
	_ = browser.response.Close()
	if browser.cmd != nil && browser.cmd.Process != nil {
		_ = browser.cmd.Process.Kill()
	}
	if browser.done != nil {
		<-browser.done
	}
	return nil
}

func browserEnvironment(options ChromiumOptions) ([]string, error) {
	base := options.Environment
	if len(base) == 0 {
		base = os.Environ()
	}
	filtered := make([]string, 0, len(base)+2)
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "LPDEST" || key == "PRINTER" || key == "CUPS_SERVER" || key == "WLR_BACKENDS" || key == "WLR_RENDERER" || key == "WLR_LIBINPUT_NO_DEVICES" || (options.RequireGraphicalSession && (key == "XDG_RUNTIME_DIR" || key == "WAYLAND_DISPLAY")) {
			continue
		}
		filtered = append(filtered, entry)
	}
	if !options.RequireGraphicalSession {
		return filtered, nil
	}
	runtimeDir := ""
	for _, entry := range base {
		if after, ok := strings.CutPrefix(entry, "XDG_RUNTIME_DIR="); ok {
			runtimeDir = after
		}
	}
	if runtimeDir == "" {
		runtimeDir = filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
	}
	runtimeDirInfo := options.runtimeDirInfo
	if runtimeDirInfo == nil {
		runtimeDirInfo = os.Lstat
	}
	if err := validateBrowserRuntimeDirWith(runtimeDir, runtimeDirInfo); err != nil {
		return nil, err
	}
	wayland := ""
	for _, entry := range base {
		if after, ok := strings.CutPrefix(entry, "WAYLAND_DISPLAY="); ok {
			wayland = after
		}
	}
	waylandSocketInfo := options.waylandSocketInfo
	if waylandSocketInfo == nil {
		waylandSocketInfo = os.Lstat
	}
	if wayland == "" {
		matches, _ := filepath.Glob(filepath.Join(runtimeDir, "wayland-*"))
		sort.Strings(matches)
		var invalidSocket error
		for _, match := range matches {
			if strings.HasSuffix(match, ".lock") {
				continue
			}
			if err := validateBrowserWaylandSocketWith(match, waylandSocketInfo); err == nil {
				wayland = filepath.Base(match)
				break
			} else if !errors.Is(err, errGraphicalSessionUnavailable) {
				invalidSocket = err
			}
		}
		if wayland == "" {
			if invalidSocket != nil {
				return nil, invalidSocket
			}
			return nil, fmt.Errorf("Wayland display socket: %w", errGraphicalSessionUnavailable)
		}
	}
	if filepath.Base(wayland) != wayland || !strings.HasPrefix(wayland, "wayland-") {
		return nil, fmt.Errorf("Wayland display socket is unsafe")
	}
	if err := validateBrowserWaylandSocketWith(filepath.Join(runtimeDir, wayland), waylandSocketInfo); err != nil {
		return nil, err
	}
	return append(filtered, "XDG_RUNTIME_DIR="+runtimeDir, "WAYLAND_DISPLAY="+wayland), nil
}

func validateBrowserRuntimeDirWith(path string, stat func(string) (os.FileInfo, error)) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 256 {
		return fmt.Errorf("XDG_RUNTIME_DIR is unsafe")
	}
	info, err := stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return errGraphicalSessionUnavailable
	}
	if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || !browserOwnedByCurrentUser(info) {
		return fmt.Errorf("XDG_RUNTIME_DIR is unavailable")
	}
	return nil
}

func browserOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(stat.Uid) == uint32(os.Getuid())
}

func validateBrowserWaylandSocketWith(path string, stat func(string) (os.FileInfo, error)) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 512 {
		return fmt.Errorf("Wayland display socket is unsafe")
	}
	info, err := stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return errGraphicalSessionUnavailable
	}
	if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || !browserOwnedByCurrentUser(info) {
		return fmt.Errorf("Wayland display socket is invalid")
	}
	return nil
}

func resolveChromiumBinary() string {
	for _, candidate := range []string{"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	if candidate, err := exec.LookPath("chromium"); err == nil {
		return candidate
	}
	if candidate, err := exec.LookPath("chromium-browser"); err == nil {
		return candidate
	}
	return "chromium"
}
