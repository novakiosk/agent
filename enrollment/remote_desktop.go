package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	remoteDesktopConfigName = "wayvnc.conf"
	remoteDesktopPort       = "5900"
	remoteDesktopWait       = 5 * time.Second
	remoteDesktopFrameLimit = 1024 * 1024
)

var remoteDesktopFailureCategories = map[string]bool{
	"unsupported": true, "graphical-session-unavailable": true, "wayvnc-missing": true,
	"config-filesystem": true, "process-start": true, "listener-unavailable": true,
	"tunnel-connect": true, "expired": true, "stop-failed": true,
}

type RemoteDesktopApplyResult struct {
	Result        string
	ErrorCategory string
	// Noop is true when the requested start already has the same live WayVNC
	// process. The relay may be between transport dials; callers should not
	// emit another lifecycle ACK while that generation recovers.
	Noop bool
}

type RemoteDesktopProcess interface {
	Wait() error
	Terminate() error
	Kill() error
	Alive() bool
}

type RemoteDesktopRunner interface {
	Start(context.Context, string, []string, []string) (RemoteDesktopProcess, error)
}

type RemoteDesktopDialers struct {
	TCP func(context.Context, string, string) (net.Conn, error)
	WSS func(context.Context, string, http.Header) (*websocket.Conn, error)
}

type RemoteDesktopManagerOptions struct {
	StateDir     string
	InstanceURL  string
	CAPath       string
	WayVNCBinary string
	Runner       RemoteDesktopRunner
	Dialers      RemoteDesktopDialers
	WaitTimeout  time.Duration
	Clock        func() time.Time
	Environment  []string
}

type remoteDesktopRuntime struct {
	mu         sync.Mutex
	generation uint64
	session    string
	process    RemoteDesktopProcess
	config     string
	cancel     context.CancelFunc
	conn       net.Conn
	socket     *websocket.Conn
}

type RemoteDesktopManager struct {
	options          RemoteDesktopManagerOptions
	runtime          remoteDesktopRuntime
	operationMu      sync.Mutex
	configRemoveHook func()
}

func NewRemoteDesktopManager(options RemoteDesktopManagerOptions) (*RemoteDesktopManager, error) {
	if strings.TrimSpace(options.StateDir) == "" {
		return nil, fmt.Errorf("remote desktop state directory is required")
	}
	if err := ensureRemoteDesktopDirectories(options.StateDir); err != nil {
		return nil, fmt.Errorf("remote desktop state directory is unsafe: %w", err)
	}
	if options.WayVNCBinary == "" {
		options.WayVNCBinary = "/usr/bin/wayvnc"
	}
	if !safeRemoteDesktopBinary(options.WayVNCBinary) {
		return nil, fmt.Errorf("remote desktop binary path is invalid")
	}
	if options.WaitTimeout <= 0 || options.WaitTimeout > 30*time.Second {
		options.WaitTimeout = remoteDesktopWait
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Runner == nil {
		options.Runner = execRemoteDesktopRunner{}
	}
	if options.Dialers.TCP == nil {
		options.Dialers.TCP = (&net.Dialer{Timeout: options.WaitTimeout}).DialContext
	}
	if options.Dialers.WSS == nil {
		dialer, err := remoteDesktopWebsocketDialer(options.CAPath)
		if err != nil {
			return nil, err
		}
		options.Dialers.WSS = func(ctx context.Context, target string, header http.Header) (*websocket.Conn, error) {
			conn, _, dialErr := dialer.DialContext(ctx, target, header)
			return conn, dialErr
		}
	}
	// A previous process may have exited after atomically installing its
	// transient config but before cleanup. Only inspect the manager-owned fixed
	// path; a symlink is never followed or removed.
	if err := removeRemoteDesktopConfig(remoteDesktopConfigPath(options.StateDir)); err != nil {
		return nil, fmt.Errorf("remote desktop config filesystem is unavailable")
	}
	return &RemoteDesktopManager{options: options}, nil
}

func safeRemoteDesktopBinary(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsAny(path, "\x00\r\n") && filepath.Clean(path) == path
}

func (manager *RemoteDesktopManager) Apply(ctx context.Context, desired *RemoteDesktopDesired) RemoteDesktopApplyResult {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	if desired == nil {
		return manager.stopCurrent()
	}
	if err := ValidateRemoteDesktopDesired(*desired, manager.options.Clock()); err != nil {
		if desired.Action == "start" {
			expires := timeFromString(desired.ExpiresAt)
			if !expires.IsZero() && !manager.options.Clock().Before(expires) {
				_ = manager.stopCurrentError()
				return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "expired"}
			}
		}
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "unsupported"}
	}
	if desired.Action == "stop" {
		return manager.stopCurrent()
	}
	if !manager.options.Clock().Before(timeFromString(desired.ExpiresAt)) {
		_ = manager.stopCurrentError()
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "expired"}
	}
	manager.runtime.mu.Lock()
	if manager.runtime.session == desired.SessionID && manager.runtime.process != nil && manager.runtime.process.Alive() {
		manager.runtime.mu.Unlock()
		return RemoteDesktopApplyResult{Result: "applied", Noop: true}
	}
	manager.runtime.mu.Unlock()
	if result := manager.stopCurrent(); result.Result == "failed" {
		return result
	}
	// Reserve a new generation before touching the shared config path. A stale
	// relay from the previous generation must not remove that path while this
	// Apply call is between cleanup and process installation.
	manager.runtime.mu.Lock()
	manager.runtime.generation++
	generation := manager.runtime.generation
	manager.runtime.mu.Unlock()
	environment := manager.graphicalEnvironment()
	if len(environment) == 0 {
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "graphical-session-unavailable"}
	}
	if _, err := os.Stat(manager.options.WayVNCBinary); err != nil {
		if _, injected := manager.options.Runner.(execRemoteDesktopRunner); injected {
			return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "wayvnc-missing"}
		}
	}
	config, err := manager.writeConfig(desired)
	if err != nil {
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "config-filesystem"}
	}
	process, err := manager.options.Runner.Start(ctx, manager.options.WayVNCBinary, []string{"--config", config}, environment)
	if err != nil {
		_ = os.Remove(config)
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "process-start"}
	}
	runContext, cancel := context.WithCancel(ctx)
	manager.runtime.mu.Lock()
	manager.runtime.session, manager.runtime.process, manager.runtime.config, manager.runtime.cancel = desired.SessionID, process, config, cancel
	manager.runtime.mu.Unlock()
	ready := make(chan error, 1)
	go manager.relay(runContext, *desired, generation, process, config, ready)
	select {
	case relayErr := <-ready:
		if relayErr != nil {
			_ = manager.stopCurrentError()
			// The relay reports startup failure only after its generation has
			// been retired. Keep this explicit fallback for the narrow race in
			// which Apply observes that report after the runtime was already
			// taken, while never touching a replacement generation.
			_ = removeRemoteDesktopConfig(config)
			return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: remoteDesktopRelayCategory(relayErr)}
		}
		return RemoteDesktopApplyResult{Result: "applied"}
	case <-time.After(manager.options.WaitTimeout):
		_ = manager.stopCurrentError()
		_ = removeRemoteDesktopConfig(config)
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "tunnel-connect"}
	case <-ctx.Done():
		_ = manager.stopCurrentError()
		_ = removeRemoteDesktopConfig(config)
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "tunnel-connect"}
	}
}

func (manager *RemoteDesktopManager) Stop() RemoteDesktopApplyResult {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	return manager.stopCurrent()
}

func (manager *RemoteDesktopManager) Close() error {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	return manager.stopCurrentError()
}

func (manager *RemoteDesktopManager) stopCurrent() RemoteDesktopApplyResult {
	if err := manager.stopCurrentError(); err != nil {
		return RemoteDesktopApplyResult{Result: "failed", ErrorCategory: "stop-failed"}
	}
	return RemoteDesktopApplyResult{Result: "applied"}
}

func (manager *RemoteDesktopManager) stopCurrentError() error {
	process, config, cancel, conn, socket := manager.takeRuntime()
	if process == nil && config == "" && cancel == nil && conn == nil && socket == nil {
		// The constructor already removes any crash-left stale config. Keeping
		// a disabled/no-session Stop in memory avoids touching the filesystem on
		// every v2 poll while policy is enabled but no session is active.
		return nil
	}
	if config == "" {
		config = remoteDesktopConfigPath(manager.options.StateDir)
	}
	processErr := cleanupRemoteDesktopRuntime(process, cancel, conn, socket, manager.options.WaitTimeout)
	manager.runtime.mu.Lock()
	defer manager.runtime.mu.Unlock()
	configErr := removeRemoteDesktopConfig(config)
	if configErr != nil {
		manager.runtime.config = config
	}
	return errors.Join(processErr, configErr)
}

func (manager *RemoteDesktopManager) takeRuntime() (RemoteDesktopProcess, string, context.CancelFunc, net.Conn, *websocket.Conn) {
	manager.runtime.mu.Lock()
	defer manager.runtime.mu.Unlock()
	process, config, cancel, conn, socket := manager.runtime.process, manager.runtime.config, manager.runtime.cancel, manager.runtime.conn, manager.runtime.socket
	manager.runtime.process, manager.runtime.config, manager.runtime.cancel, manager.runtime.conn, manager.runtime.socket, manager.runtime.session = nil, "", nil, nil, nil, ""
	return process, config, cancel, conn, socket
}

func cleanupRemoteDesktopRuntime(process RemoteDesktopProcess, cancel context.CancelFunc, conn net.Conn, socket *websocket.Conn, waitTimeout time.Duration) error {
	var firstErr error
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if socket != nil {
		_ = socket.Close()
	}
	if process != nil && process.Alive() {
		terminated := false
		if err := process.Terminate(); err != nil {
			if errors.Is(err, os.ErrProcessDone) {
				terminated = true
			} else {
				firstErr = err
			}
		} else {
			terminated = true
		}
		wait := make(chan error, 1)
		go func() { wait <- process.Wait() }()
		select {
		case waitErr := <-wait:
			if firstErr == nil && !terminated && waitErr != nil && !errors.Is(waitErr, os.ErrProcessDone) {
				firstErr = waitErr
			}
		case <-time.After(waitTimeout):
			if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

func remoteDesktopConfigPath(stateDir string) string {
	return filepath.Join(stateDir, "remote-desktop", remoteDesktopConfigName)
}

func removeRemoteDesktopConfig(path string) error {
	// Check both manager-owned directories. This prevents cleanup from
	// following a replaced state-dir or remote-desktop symlink, including after
	// a process crash when only the fixed config path is available.
	stateDir := filepath.Dir(filepath.Dir(path))
	if err := ensureRemoteDesktopDirectories(stateDir); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("remote desktop config path is unsafe")
	}
	return os.Remove(path)
}

// ensureRemoteDesktopDirectories establishes the ownership boundary for the
// only directory tree in which the transient WayVNC config may exist. State
// is created by enrollment before a manager is constructed; the nested
// directory is created here once, then both directories must remain private
// and owned by the effective agent user. No chmod/chown is attempted on an
// existing path so a deployment mistake fails closed.
func ensureRemoteDesktopDirectories(stateDir string) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("remote desktop state directory is invalid")
	}
	if err := validateRemoteDesktopDirectory(stateDir); err != nil {
		return err
	}
	remoteDir := filepath.Join(stateDir, "remote-desktop")
	if _, err := os.Lstat(remoteDir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(remoteDir, 0700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return validateRemoteDesktopDirectory(remoteDir)
}

func validateRemoteDesktopDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("remote desktop directory is not a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Geteuid()) {
		return fmt.Errorf("remote desktop directory owner is unsafe")
	}
	return nil
}

func (manager *RemoteDesktopManager) graphicalEnvironment() []string {
	if manager.options.Environment != nil {
		return append([]string(nil), manager.options.Environment...)
	}
	environment, err := browserEnvironment(ChromiumOptions{Environment: os.Environ(), RequireGraphicalSession: true})
	if err != nil {
		return nil
	}
	socket, err := discoverSwaySocket()
	if err != nil {
		return nil
	}
	return mergeRuntimeEnvironment(environment, []string{"SWAYSOCK=" + socket})
}

func (manager *RemoteDesktopManager) writeConfig(desired *RemoteDesktopDesired) (string, error) {
	if err := ensureRemoteDesktopDirectories(manager.options.StateDir); err != nil {
		return "", err
	}
	root := filepath.Join(manager.options.StateDir, "remote-desktop")
	path := filepath.Join(root, remoteDesktopConfigName)
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("remote desktop config path is unsafe")
	}
	contents := "address=127.0.0.1\nport=5900\nenable_auth=true\nrelax_encryption=true\nusername=" + desired.WayVNCUsername + "\npassword=" + desired.WayVNCPassword + "\n"
	temporary, err := os.CreateTemp(root, ".wayvnc.conf.tmp-*")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err := temporary.WriteString(contents); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return "", err
	}
	// Track the manager-owned path even when tests or a startup failure call
	// writeConfig before a child process is installed. Stop then removes this
	// one known file once, while subsequent inactive stops stay in-memory.
	manager.runtime.mu.Lock()
	manager.runtime.config = path
	manager.runtime.mu.Unlock()
	return path, nil
}

func (manager *RemoteDesktopManager) relay(ctx context.Context, desired RemoteDesktopDesired, generation uint64, process RemoteDesktopProcess, config string, ready chan<- error) {
	readyOnce := sync.Once{}
	reportReady := func(err error) {
		readyOnce.Do(func() {
			select {
			case ready <- err:
			default:
			}
		})
	}
	if desired.Action != "start" {
		reportReady(errors.New("unsupported"))
		return
	}
	target, err := remoteDesktopWebsocketURL(manager.options.InstanceURL)
	if err != nil {
		manager.failRuntime(desired.SessionID, generation, process, config)
		reportReady(errors.New("tunnel-connect"))
		return
	}
	header := http.Header{"Authorization": []string{"Bearer " + desired.DeviceToken}}
	// Apply must fail promptly if WayVNC never opens its loopback listener, but
	// after the first pair is ready a transport loss is recoverable. The child
	// process, credentials, and config therefore remain owned by this
	// generation while the relay redials both sides.
	startupDeadline := time.NewTimer(manager.options.WaitTimeout)
	defer startupDeadline.Stop()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go manager.watchRuntime(ctx, watchDone, desired.SessionID, generation, process, timeFromString(desired.ExpiresAt))
	backoff := remoteDesktopReconnectInitial
	readyReported := false
	for {
		if !manager.options.Clock().Before(timeFromString(desired.ExpiresAt)) {
			manager.failRuntime(desired.SessionID, generation, process, config)
			if !readyReported {
				reportReady(errors.New("expired"))
			}
			return
		}
		if !process.Alive() {
			manager.failRuntime(desired.SessionID, generation, process, config)
			if !readyReported {
				reportReady(errors.New("tunnel-connect"))
			}
			return
		}
		raw, rawErr := manager.dialRemoteDesktopTCP(ctx)
		if rawErr != nil || raw == nil {
			var startup <-chan time.Time
			if !readyReported {
				startup = startupDeadline.C
			}
			if !manager.waitRemoteDesktopBackoff(ctx, backoff, startup) {
				manager.failRuntime(desired.SessionID, generation, process, config)
				if !readyReported {
					reportReady(errors.New("listener-unavailable"))
				}
				return
			}
			backoff = nextRemoteDesktopBackoff(backoff)
			continue
		}
		if !manager.installRemoteDesktopConn(desired.SessionID, generation, raw) {
			_ = raw.Close()
			return
		}
		socket, socketErr := manager.dialRemoteDesktopWSS(ctx, target, header)
		if socketErr != nil || socket == nil {
			manager.clearRemoteDesktopTransport(desired.SessionID, generation, raw, nil)
			_ = raw.Close()
			var startup <-chan time.Time
			if !readyReported {
				startup = startupDeadline.C
			}
			if !manager.waitRemoteDesktopBackoff(ctx, backoff, startup) {
				manager.failRuntime(desired.SessionID, generation, process, config)
				if !readyReported {
					reportReady(errors.New("tunnel-connect"))
				}
				return
			}
			backoff = nextRemoteDesktopBackoff(backoff)
			continue
		}
		if !manager.installRemoteDesktopSocket(desired.SessionID, generation, socket) {
			_ = raw.Close()
			_ = socket.Close()
			return
		}
		if !readyReported {
			readyReported = true
			reportReady(nil)
		}
		backoff = remoteDesktopReconnectInitial
		manager.pumpRemoteDesktopPair(ctx, raw, socket)
		manager.clearRemoteDesktopTransport(desired.SessionID, generation, raw, socket)
		_ = raw.Close()
		_ = socket.Close()
		if ctx.Err() != nil || !process.Alive() || !manager.options.Clock().Before(timeFromString(desired.ExpiresAt)) {
			manager.failRuntime(desired.SessionID, generation, process, config)
			return
		}
		// A fresh TCP dial is intentional: WayVNC's RFB stream cannot be
		// resumed halfway through a handshake by a replacement noVNC client.
		if !manager.waitRemoteDesktopBackoff(ctx, backoff, nil) {
			manager.failRuntime(desired.SessionID, generation, process, config)
			return
		}
		backoff = nextRemoteDesktopBackoff(backoff)
	}
}

const (
	remoteDesktopReconnectInitial = 50 * time.Millisecond
	remoteDesktopReconnectMax     = time.Second
)

func nextRemoteDesktopBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return remoteDesktopReconnectInitial
	}
	if current >= remoteDesktopReconnectMax {
		return remoteDesktopReconnectMax
	}
	if current > remoteDesktopReconnectMax/2 {
		return remoteDesktopReconnectMax
	}
	return current * 2
}

func (manager *RemoteDesktopManager) waitRemoteDesktopBackoff(ctx context.Context, delay time.Duration, startup <-chan time.Time) bool {
	if delay <= 0 {
		delay = remoteDesktopReconnectInitial
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	case <-startup:
		return false
	}
}

func (manager *RemoteDesktopManager) dialRemoteDesktopTCP(ctx context.Context) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, manager.options.WaitTimeout)
	defer cancel()
	return manager.options.Dialers.TCP(dialCtx, "tcp", "127.0.0.1:"+remoteDesktopPort)
}

func (manager *RemoteDesktopManager) dialRemoteDesktopWSS(ctx context.Context, target string, header http.Header) (*websocket.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, manager.options.WaitTimeout)
	defer cancel()
	return manager.options.Dialers.WSS(dialCtx, target, header)
}

func (manager *RemoteDesktopManager) pumpRemoteDesktopPair(ctx context.Context, raw net.Conn, socket *websocket.Conn) {
	pumpContext, pumpCancel := context.WithCancel(ctx)
	defer pumpCancel()
	var group sync.WaitGroup
	firstPumpDone := make(chan struct{})
	var firstPumpOnce sync.Once
	pumpDone := func() {
		firstPumpOnce.Do(func() {
			close(firstPumpDone)
			pumpCancel()
			_ = raw.Close()
			_ = socket.Close()
		})
	}
	group.Add(2)
	go func() { defer group.Done(); manager.rawToWebsocket(pumpContext, raw, socket); pumpDone() }()
	go func() { defer group.Done(); manager.websocketToRaw(pumpContext, socket, raw); pumpDone() }()
	select {
	case <-firstPumpDone:
	case <-ctx.Done():
		pumpDone()
	}
	group.Wait()
}

func (manager *RemoteDesktopManager) clearRemoteDesktopTransport(session string, generation uint64, raw net.Conn, socket *websocket.Conn) {
	manager.runtime.mu.Lock()
	defer manager.runtime.mu.Unlock()
	if manager.runtime.session != session || manager.runtime.generation != generation {
		return
	}
	if raw != nil && manager.runtime.conn == raw {
		manager.runtime.conn = nil
	}
	if socket != nil && manager.runtime.socket == socket {
		manager.runtime.socket = nil
	}
}

func (manager *RemoteDesktopManager) watchRuntime(ctx context.Context, done <-chan struct{}, session string, generation uint64, process RemoteDesktopProcess, expires time.Time) {
	interval := time.NewTicker(100 * time.Millisecond)
	defer interval.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			manager.closeRemoteDesktopTransport(session, generation)
			return
		case <-interval.C:
			if !process.Alive() || (!expires.IsZero() && !manager.options.Clock().Before(expires)) {
				manager.closeRemoteDesktopTransport(session, generation)
				return
			}
		}
	}
}

func (manager *RemoteDesktopManager) closeRemoteDesktopTransport(session string, generation uint64) {
	manager.runtime.mu.Lock()
	if manager.runtime.session != session || manager.runtime.generation != generation {
		manager.runtime.mu.Unlock()
		return
	}
	raw, socket := manager.runtime.conn, manager.runtime.socket
	manager.runtime.mu.Unlock()
	if raw != nil {
		_ = raw.Close()
	}
	if socket != nil {
		_ = socket.Close()
	}
}

func (manager *RemoteDesktopManager) rawToWebsocket(ctx context.Context, raw net.Conn, socket *websocket.Conn) {
	buffer := make([]byte, remoteDesktopFrameLimit)
	for {
		count, err := raw.Read(buffer)
		if count > 0 {
			_ = socket.SetWriteDeadline(time.Now().Add(manager.options.WaitTimeout))
			if socket.WriteMessage(websocket.BinaryMessage, buffer[:count]) != nil {
				return
			}
		}
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (manager *RemoteDesktopManager) websocketToRaw(ctx context.Context, socket *websocket.Conn, raw net.Conn) {
	socket.SetReadLimit(remoteDesktopFrameLimit)
	for {
		messageType, data, err := socket.ReadMessage()
		if err != nil || messageType != websocket.BinaryMessage || len(data) > remoteDesktopFrameLimit {
			return
		}
		_ = raw.SetWriteDeadline(time.Now().Add(manager.options.WaitTimeout))
		if _, err := raw.Write(data); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func remoteDesktopRelayCategory(err error) string {
	switch err.Error() {
	case "expired":
		return "expired"
	case "listener-unavailable":
		return "listener-unavailable"
	default:
		return "tunnel-connect"
	}
}

func (manager *RemoteDesktopManager) failRuntime(session string, generation uint64, process RemoteDesktopProcess, config string) {
	manager.runtime.mu.Lock()
	owned := manager.runtime.session == session && manager.runtime.generation == generation
	if owned {
		process, config, cancel, conn, socket := manager.runtime.process, manager.runtime.config, manager.runtime.cancel, manager.runtime.conn, manager.runtime.socket
		manager.runtime.process, manager.runtime.config, manager.runtime.cancel, manager.runtime.conn, manager.runtime.socket, manager.runtime.session = nil, "", nil, nil, nil, ""
		manager.runtime.mu.Unlock()
		_ = cleanupRemoteDesktopRuntime(process, cancel, conn, socket, manager.options.WaitTimeout)
		// The fixed config path is shared by generations. Re-check ownership
		// while holding runtime.mu across the unlink: otherwise a replacement
		// Apply can install fresh credentials between the check and Remove.
		manager.removeConfigForGeneration(generation, config)
		return
	}
	manager.runtime.mu.Unlock()
	// A stale relay still owns its captured child and sockets, but must never
	// touch the shared config path. The current owner (or Stop) is responsible
	// for unlinking it under its own generation lock.
	_ = cleanupRemoteDesktopRuntime(process, nil, nil, nil, manager.options.WaitTimeout)
}

func (manager *RemoteDesktopManager) removeConfigForGeneration(generation uint64, config string) {
	if config == "" {
		return
	}
	manager.runtime.mu.Lock()
	defer manager.runtime.mu.Unlock()
	if manager.runtime.generation != generation || manager.runtime.session != "" || manager.runtime.config != "" {
		return
	}
	if manager.configRemoveHook != nil {
		// The hook is private and test-only. It deliberately runs while the
		// ownership lock is held so tests can prove a replacement writer cannot
		// pass the generation check before this unlink completes.
		manager.configRemoveHook()
	}
	if err := removeRemoteDesktopConfig(config); err != nil {
		manager.runtime.config = config
	}
}

func (manager *RemoteDesktopManager) installRemoteDesktopConn(session string, generation uint64, conn net.Conn) bool {
	manager.runtime.mu.Lock()
	defer manager.runtime.mu.Unlock()
	if manager.runtime.session != session || manager.runtime.generation != generation {
		return false
	}
	manager.runtime.conn = conn
	return true
}

func (manager *RemoteDesktopManager) installRemoteDesktopSocket(session string, generation uint64, socket *websocket.Conn) bool {
	manager.runtime.mu.Lock()
	defer manager.runtime.mu.Unlock()
	if manager.runtime.session != session || manager.runtime.generation != generation {
		return false
	}
	manager.runtime.socket = socket
	return true
}

func timeFromString(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

type execRemoteDesktopRunner struct{}
type execRemoteDesktopProcess struct {
	process *os.Process
	done    chan struct{}
	mu      sync.Mutex
	waitErr error
}

func (execRemoteDesktopRunner) Start(ctx context.Context, name string, args []string, environment []string) (RemoteDesktopProcess, error) {
	command := exec.Command(name, args...)
	command.Env = environment
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &execRemoteDesktopProcess{process: command.Process, done: make(chan struct{})}
	go func() {
		err := command.Wait()
		process.mu.Lock()
		process.waitErr = err
		close(process.done)
		process.mu.Unlock()
	}()
	go process.watchCancellation(ctx)
	return process, nil
}
func (process *execRemoteDesktopProcess) watchCancellation(ctx context.Context) {
	select {
	case <-ctx.Done():
		if process.Alive() {
			_ = process.Terminate()
		}
	case <-process.done:
	}
}

func (process *execRemoteDesktopProcess) Wait() error {
	<-process.done
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}
func (process *execRemoteDesktopProcess) Terminate() error {
	return process.process.Signal(syscall.SIGTERM)
}
func (process *execRemoteDesktopProcess) Kill() error { return process.process.Kill() }
func (process *execRemoteDesktopProcess) Alive() bool {
	select {
	case <-process.done:
		return false
	default:
		return process.process != nil
	}
}

func remoteDesktopWebsocketURL(instance string) (string, error) {
	parsed, err := validateInstance(instance)
	if err != nil {
		return "", err
	}
	parsed.Scheme = "wss"
	parsed.Path = RemoteDesktopTunnelPath
	parsed.RawQuery, parsed.Fragment = "", ""
	return parsed.String(), nil
}

func remoteDesktopWebsocketDialer(caPath string) (*websocket.Dialer, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caPath != "" {
		data, readErr := os.ReadFile(caPath)
		if readErr != nil || !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("configured CA certificate could not be loaded")
		}
	}
	return &websocket.Dialer{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, HandshakeTimeout: remoteDesktopWait}, nil
}
