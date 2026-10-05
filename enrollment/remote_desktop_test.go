package enrollment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func privateRemoteDesktopTempDir(t *testing.T) string {
	t.Helper()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

func testRemoteDesktopDesired(now time.Time, action string) RemoteDesktopDesired {
	issued := now.UTC().Format(time.RFC3339Nano)
	expires := now.Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
	desired := RemoteDesktopDesired{
		Version: ProtocolVersion, Type: "remote-desktop.desired", SessionID: "remote-session",
		Action: action, IssuedAt: issued, ExpiresAt: expires, TunnelPath: RemoteDesktopTunnelPath,
	}
	if action == "start" {
		desired.DeviceToken = strings.Repeat("d", 32)
		desired.WayVNCUsername = "nova-user"
		desired.WayVNCPassword = strings.Repeat("p", 32)
	}
	return desired
}

func TestValidateRemoteDesktopDesiredIsStrictAndBounded(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	if err := ValidateRemoteDesktopDesired(testRemoteDesktopDesired(now, "start"), now); err != nil {
		t.Fatalf("valid desired rejected: %v", err)
	}
	invalid := testRemoteDesktopDesired(now, "start")
	invalid.TunnelPath = "wss://attacker.example/"
	if err := ValidateRemoteDesktopDesired(invalid, now); err == nil {
		t.Fatal("arbitrary tunnel path accepted")
	}
	invalid = testRemoteDesktopDesired(now, "stop")
	invalid.DeviceToken = "credential"
	if err := ValidateRemoteDesktopDesired(invalid, now); err == nil {
		t.Fatal("stop desired accepted credentials")
	}
	invalid = testRemoteDesktopDesired(now, "start")
	invalid.IssuedAt = "2026-08-28T14:00:00+02:00"
	if err := ValidateRemoteDesktopDesired(invalid, now); err == nil {
		t.Fatal("non-canonical timestamp accepted")
	}
	invalid = testRemoteDesktopDesired(now, "start")
	invalid.IssuedAt = "2026-08-28T13:00:00Z"
	invalid.ExpiresAt = "2026-08-28T13:10:00Z"
	if err := ValidateRemoteDesktopDesired(invalid, now); err == nil {
		t.Fatal("future desired timestamp accepted")
	}
	invalid = testRemoteDesktopDesired(now, "start")
	invalid.DeviceToken = strings.Repeat("!", 32)
	if err := ValidateRemoteDesktopDesired(invalid, now); err == nil {
		t.Fatal("unsafe device token accepted")
	}
}

func TestRemoteDesktopConfigIsFixed0600AndStaleConfigIsRemoved(t *testing.T) {
	stateDir := privateRemoteDesktopTempDir(t)
	configDir := filepath.Join(stateDir, "remote-desktop")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(configDir, remoteDesktopConfigName)
	if err := os.WriteFile(stale, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
		StateDir: stateDir, InstanceURL: "https://control.example",
		Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale config was not removed: %v", err)
	}
	desired := testRemoteDesktopDesired(time.Now().UTC(), "start")
	path, err := manager.writeConfig(&desired)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "address=127.0.0.1\nport=5900\nenable_auth=true\nrelax_encryption=true\nusername=" + desired.WayVNCUsername + "\npassword=" + desired.WayVNCPassword + "\n"
	if string(data) != want {
		t.Fatalf("unexpected fixed WayVNC config: %q", string(data))
	}
	if result := manager.Stop(); result.Result != "applied" {
		t.Fatalf("stop result = %#v", result)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config remained after stop: %v", err)
	}
}

func TestRemoteDesktopManagerRejectsUnsafeDirectoryPermissions(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{StateDir: stateDir, InstanceURL: "https://control.example"}); err == nil {
		t.Fatal("world-readable state directory was accepted")
	}

	stateDir = privateRemoteDesktopTempDir(t)
	configDir := filepath.Join(stateDir, "remote-desktop")
	if err := os.Mkdir(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{StateDir: stateDir, InstanceURL: "https://control.example"}); err == nil {
		t.Fatal("world-readable remote-desktop directory was accepted")
	}
}

type fakeRemoteDesktopProcess struct {
	mu         sync.Mutex
	alive      bool
	terminated bool
	done       chan struct{}
}

func newFakeRemoteDesktopProcess() *fakeRemoteDesktopProcess {
	return &fakeRemoteDesktopProcess{alive: true, done: make(chan struct{})}
}

func (process *fakeRemoteDesktopProcess) Wait() error {
	<-process.done
	return nil
}

func (process *fakeRemoteDesktopProcess) Terminate() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	if !process.alive {
		return errors.New("process already done")
	}
	process.alive = false
	process.terminated = true
	close(process.done)
	return nil
}

func (process *fakeRemoteDesktopProcess) Kill() error { return process.Terminate() }

func (process *fakeRemoteDesktopProcess) Alive() bool {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.alive
}

type blockingRemoteDesktopProcess struct {
	mu         sync.Mutex
	alive      bool
	exited     bool
	terminated chan struct{}
	release    chan struct{}
	termOnce   sync.Once
}

func newBlockingRemoteDesktopProcess() *blockingRemoteDesktopProcess {
	return &blockingRemoteDesktopProcess{alive: true, terminated: make(chan struct{}), release: make(chan struct{})}
}

func (process *blockingRemoteDesktopProcess) Wait() error {
	<-process.release
	process.mu.Lock()
	process.exited = true
	process.mu.Unlock()
	return nil
}

func (process *blockingRemoteDesktopProcess) Terminate() error {
	process.termOnce.Do(func() { close(process.terminated) })
	return nil
}

func (process *blockingRemoteDesktopProcess) Kill() error { return process.Terminate() }

func (process *blockingRemoteDesktopProcess) Alive() bool {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.alive && !process.exited
}

type fakeRemoteDesktopRunner struct {
	mu       sync.Mutex
	starts   int
	commands []struct {
		name string
		args []string
		env  []string
	}
	processes []*fakeRemoteDesktopProcess
}

func (runner *fakeRemoteDesktopRunner) Start(_ context.Context, name string, args []string, environment []string) (RemoteDesktopProcess, error) {
	process := newFakeRemoteDesktopProcess()
	runner.mu.Lock()
	runner.starts++
	runner.commands = append(runner.commands, struct {
		name string
		args []string
		env  []string
	}{name: name, args: append([]string(nil), args...), env: append([]string(nil), environment...)})
	runner.processes = append(runner.processes, process)
	runner.mu.Unlock()
	return process, nil
}

func (runner *fakeRemoteDesktopRunner) count() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.starts
}

func TestRemoteDesktopApplyWaitsForTunnelAndCleansFailedStart(t *testing.T) {
	stateDir := privateRemoteDesktopTempDir(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	runner := &fakeRemoteDesktopRunner{}
	var rawPeer net.Conn
	manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
		StateDir: stateDir, InstanceURL: "https://control.example", Runner: runner,
		Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
		Clock:       func() time.Time { return now }, WaitTimeout: 150 * time.Millisecond,
		Dialers: RemoteDesktopDialers{
			TCP: func(context.Context, string, string) (net.Conn, error) {
				local, peer := net.Pipe()
				rawPeer = peer
				return local, nil
			},
			WSS: func(context.Context, string, http.Header) (*websocket.Conn, error) {
				return nil, errors.New("control plane unavailable")
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	desired := testRemoteDesktopDesired(now, "start")
	result := manager.Apply(context.Background(), &desired)
	if result.Result != "failed" || result.ErrorCategory != "tunnel-connect" {
		t.Fatalf("failed tunnel result = %#v", result)
	}
	if rawPeer != nil {
		_ = rawPeer.Close()
	}
	if runner.count() != 1 {
		t.Fatalf("runner starts = %d, want one", runner.count())
	}
	runner.mu.Lock()
	process := runner.processes[0]
	runner.mu.Unlock()
	process.mu.Lock()
	terminated := process.terminated
	process.mu.Unlock()
	if !terminated {
		t.Fatal("failed tunnel left WayVNC process alive")
	}
	if _, statErr := os.Stat(remoteDesktopConfigPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("failed tunnel left config: %v", statErr)
	}
}

func TestRemoteDesktopApplySameStartAndStopAreIdempotent(t *testing.T) {
	for _, companion := range []bool{false, true} {
		t.Run(fmt.Sprint(companion), func(t *testing.T) {
			stateDir := privateRemoteDesktopTempDir(t)
			now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
			runner := &fakeRemoteDesktopRunner{}
			var peer net.Conn
			var serverConn *websocket.Conn
			serverReady := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
				connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
				if upgradeErr != nil {
					return
				}
				serverConn = connection
				close(serverReady)
				_, _, _ = connection.ReadMessage()
			}))
			defer server.Close()
			manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
				StateDir: stateDir, InstanceURL: "https://control.example", Runner: runner,
				Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
				Clock:       func() time.Time { return now }, WaitTimeout: time.Second,
				Dialers: RemoteDesktopDialers{
					TCP: func(context.Context, string, string) (net.Conn, error) {
						local, remote := net.Pipe()
						peer = remote
						return local, nil
					},
					WSS: func(ctx context.Context, _ string, header http.Header) (*websocket.Conn, error) {
						if header.Get("Authorization") == "" {
							return nil, errors.New("missing tunnel authorization")
						}
						target := "ws" + strings.TrimPrefix(server.URL, "http")
						connection, _, dialErr := websocket.DefaultDialer.DialContext(ctx, target, header)
						return connection, dialErr
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if companion {
				manager.options.LocalStart = func(ctx context.Context, session WayVNCSession) (RemoteDesktopProcess, error) {
					if session.SessionID != "remote-session" || session.Username != "nova-user" || session.Password != strings.Repeat("p", 32) {
						t.Fatal("companion credentials changed")
					}
					return runner.Start(ctx, "/usr/bin/wayvnc", nil, nil)
				}
			}
			desired := testRemoteDesktopDesired(now, "start")
			if result := manager.Apply(context.Background(), &desired); result.Result != "applied" {
				t.Fatalf("start result = %#v", result)
			}
			select {
			case <-serverReady:
			case <-time.After(time.Second):
				t.Fatal("device WSS did not connect before Apply returned")
			}
			if result := manager.Apply(context.Background(), &desired); result.Result != "applied" || !result.Noop {
				t.Fatalf("same start result = %#v, want applied no-op", result)
			}
			if runner.count() != 1 {
				t.Fatalf("same start spawned %d processes", runner.count())
			}
			if _, err := peer.Write([]byte("RFB")); err != nil {
				t.Fatalf("raw peer write: %v", err)
			}
			if result := manager.Stop(); result.Result != "applied" {
				t.Fatalf("stop result = %#v", result)
			}
			if result := manager.Stop(); result.Result != "applied" {
				t.Fatalf("duplicate stop result = %#v", result)
			}
			if _, statErr := os.Stat(remoteDesktopConfigPath(stateDir)); !os.IsNotExist(statErr) {
				t.Fatalf("stop left config: %v", statErr)
			}
			_ = peer.Close()
			if serverConn != nil {
				_ = serverConn.Close()
			}
		})
	}
}

func TestRemoteDesktopNoopApplyDoesNotEmitHeartbeatAck(t *testing.T) {
	stateDir := privateRemoteDesktopTempDir(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	process := newFakeRemoteDesktopProcess()
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	manager := &RemoteDesktopManager{options: RemoteDesktopManagerOptions{StateDir: stateDir, Clock: func() time.Time { return now }, WaitTimeout: time.Second}}
	manager.runtime = remoteDesktopRuntime{
		session: "remote-session", process: process, conn: raw, socket: &websocket.Conn{},
	}
	desired := testRemoteDesktopDesired(now, "start")
	state := State{}
	snapshot := DesiredSnapshot{SessionID: "managed-session", RemoteDesktop: &desired}
	client := Client{Now: func() time.Time { return now }}
	if err := client.applyRemoteDesktopAndAcknowledge(context.Background(), &state, Identity{}, nil, snapshot, manager); err != nil {
		t.Fatalf("no-op remote desktop apply: %v", err)
	}
	if state.RemoteDesktopAckSequence != 0 {
		t.Fatalf("no-op remote desktop apply advanced ACK sequence to %d", state.RemoteDesktopAckSequence)
	}
	process.mu.Lock()
	process.alive = false
	process.mu.Unlock()
}

func TestRemoteDesktopStaleRelayCannotUnlinkReplacementConfig(t *testing.T) {
	stateDir := privateRemoteDesktopTempDir(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
		StateDir: stateDir, InstanceURL: "https://control.example",
		Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
		Clock:       func() time.Time { return now }, WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldDesired := testRemoteDesktopDesired(now, "start")
	oldDesired.SessionID = "old-session"
	oldConfig, err := manager.writeConfig(&oldDesired)
	if err != nil {
		t.Fatal(err)
	}
	oldProcess := newBlockingRemoteDesktopProcess()
	manager.runtime.mu.Lock()
	manager.runtime.generation = 1
	manager.runtime.session = oldDesired.SessionID
	manager.runtime.process = oldProcess
	manager.runtime.config = oldConfig
	manager.runtime.mu.Unlock()
	newDesired := testRemoteDesktopDesired(now, "start")
	newDesired.SessionID = "new-session"
	newDesired.WayVNCPassword = strings.Repeat("n", 32)
	newProcess := newFakeRemoteDesktopProcess()
	replacementAttempted := make(chan struct{})
	replacementAcquired := make(chan struct{})
	replacementAcquiredEarly := make(chan struct{})
	replacementResult := make(chan struct {
		path string
		err  error
	}, 1)
	manager.configRemoveHook = func() {
		go func() {
			// This goroutine is deliberately started at the unlink boundary. The
			// generation-atomic implementation keeps it blocked on runtime.mu
			// until the stale unlink completes.
			close(replacementAttempted)
			manager.runtime.mu.Lock()
			close(replacementAcquired)
			manager.runtime.generation = 2
			manager.runtime.session = newDesired.SessionID
			manager.runtime.process = newProcess
			manager.runtime.mu.Unlock()
			path, writeErr := manager.writeConfig(&newDesired)
			replacementResult <- struct {
				path string
				err  error
			}{path: path, err: writeErr}
		}()
		<-replacementAttempted
		select {
		case <-replacementAcquired:
			close(replacementAcquiredEarly)
		case <-time.After(20 * time.Millisecond):
		}
	}

	staleDone := make(chan struct{})
	go func() {
		manager.failRuntime(oldDesired.SessionID, 1, oldProcess, oldConfig)
		close(staleDone)
	}()
	select {
	case <-oldProcess.terminated:
	case <-time.After(time.Second):
		t.Fatal("stale relay did not enter cleanup")
	}

	// The stale relay is blocked in process.Wait. At its unlink boundary, the
	// replacement writer attempts to advance the generation and write fresh
	// credentials. The writer must remain blocked until the old unlink is done.
	close(oldProcess.release)
	select {
	case <-staleDone:
	case <-time.After(time.Second):
		t.Fatal("stale relay cleanup did not finish")
	}
	var replacement struct {
		path string
		err  error
	}
	select {
	case replacement = <-replacementResult:
	case <-time.After(time.Second):
		t.Fatal("replacement Apply did not complete after stale unlink")
	}
	if replacement.err != nil {
		t.Fatalf("replacement config write failed: %v", replacement.err)
	}
	select {
	case <-replacementAcquiredEarly:
		t.Fatal("replacement acquired runtime ownership before stale unlink completed")
	default:
	}
	newConfig := replacement.path
	data, err := os.ReadFile(newConfig)
	if err != nil {
		t.Fatalf("replacement config was removed by stale relay: %v", err)
	}
	if !strings.Contains(string(data), "password="+newDesired.WayVNCPassword+"\n") {
		t.Fatalf("replacement config contains stale credentials: %q", string(data))
	}
	manager.runtime.mu.Lock()
	manager.runtime.session = newDesired.SessionID
	manager.runtime.process = newProcess
	manager.runtime.mu.Unlock()
	if result := manager.Stop(); result.Result != "applied" {
		t.Fatalf("replacement stop result = %#v", result)
	}
}

func TestRemoteDesktopIdleRelaySurvivesWaitTimeoutAndStopsOnCancellation(t *testing.T) {
	stateDir := privateRemoteDesktopTempDir(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	runner := &fakeRemoteDesktopRunner{}
	const waitTimeout = 25 * time.Millisecond
	var peer net.Conn
	serverReceived := make(chan []byte, 1)
	serverReady := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		defer connection.Close()
		close(serverReady)
		_, data, readErr := connection.ReadMessage()
		if readErr == nil {
			serverReceived <- append([]byte(nil), data...)
		}
	}))
	defer server.Close()
	manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
		StateDir: stateDir, InstanceURL: "https://control.example", Runner: runner,
		Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
		Clock:       func() time.Time { return now }, WaitTimeout: waitTimeout,
		Dialers: RemoteDesktopDialers{
			TCP: func(context.Context, string, string) (net.Conn, error) {
				local, remote := net.Pipe()
				peer = remote
				return local, nil
			},
			WSS: func(ctx context.Context, _ string, header http.Header) (*websocket.Conn, error) {
				if header.Get("Authorization") == "" {
					return nil, errors.New("missing tunnel authorization")
				}
				target := "ws" + strings.TrimPrefix(server.URL, "http")
				connection, _, dialErr := websocket.DefaultDialer.DialContext(ctx, target, header)
				return connection, dialErr
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	desired := testRemoteDesktopDesired(now, "start")
	if result := manager.Apply(context.Background(), &desired); result.Result != "applied" {
		t.Fatalf("start result = %#v", result)
	}
	select {
	case <-serverReady:
	case <-time.After(time.Second):
		t.Fatal("device WSS did not connect before Apply returned")
	}

	// An idle RFB stream must not inherit the startup/tunnel wait timeout.
	// The timer makes the assertion deterministic relative to that bound,
	// while the later write proves the original raw connection is still live.
	timer := time.NewTimer(4 * waitTimeout)
	select {
	case <-timer.C:
	case <-time.After(time.Second):
		t.Fatal("idle relay test timer did not fire")
	}
	defer peer.Close()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := peer.Write([]byte("RFB idle survives"))
		writeDone <- writeErr
	}()
	select {
	case data := <-serverReceived:
		if string(data) != "RFB idle survives" {
			t.Fatalf("relayed idle data = %q", data)
		}
	case <-time.After(time.Second):
		t.Fatal("idle raw traffic was not relayed")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("raw peer write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("raw peer write did not complete")
	}

	if result := manager.Stop(); result.Result != "applied" {
		t.Fatalf("stop result = %#v", result)
	}
	if runner.count() != 1 {
		t.Fatalf("runner starts = %d, want one", runner.count())
	}
	runner.mu.Lock()
	process := runner.processes[0]
	runner.mu.Unlock()
	process.mu.Lock()
	terminated := process.terminated
	process.mu.Unlock()
	if !terminated {
		t.Fatal("cancellation left WayVNC process alive")
	}
	if _, statErr := os.Stat(remoteDesktopConfigPath(stateDir)); !os.IsNotExist(statErr) {
		t.Fatalf("stop left config: %v", statErr)
	}
}

func TestRemoteDesktopRelayRedialsAfterStartupDeadlineWithoutRestartingWayVNC(t *testing.T) {
	stateDir := privateRemoteDesktopTempDir(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	runner := &fakeRemoteDesktopRunner{}
	tcpPeers := make(chan net.Conn, 4)
	serverSockets := make(chan *websocket.Conn, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		serverSockets <- connection
	}))
	defer server.Close()
	manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
		StateDir: stateDir, InstanceURL: "https://control.example", Runner: runner,
		Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
		Clock:       func() time.Time { return now }, WaitTimeout: 25 * time.Millisecond,
		Dialers: RemoteDesktopDialers{
			TCP: func(context.Context, string, string) (net.Conn, error) {
				local, peer := net.Pipe()
				tcpPeers <- peer
				return local, nil
			},
			WSS: func(ctx context.Context, _ string, header http.Header) (*websocket.Conn, error) {
				if header.Get("Authorization") == "" {
					return nil, errors.New("missing tunnel authorization")
				}
				target := "ws" + strings.TrimPrefix(server.URL, "http")
				connection, _, dialErr := websocket.DefaultDialer.DialContext(ctx, target, header)
				return connection, dialErr
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	desired := testRemoteDesktopDesired(now, "start")
	if result := manager.Apply(context.Background(), &desired); result.Result != "applied" {
		t.Fatalf("start result = %#v", result)
	}
	firstSocket := <-serverSockets
	firstPeer := <-tcpPeers
	// Let the pre-ready startup timer expire. A later transport loss must not
	// inherit that one-shot deadline after Apply has reported the first pair.
	timer := time.NewTimer(4 * manager.options.WaitTimeout)
	<-timer.C
	_ = firstSocket.Close()
	defer firstPeer.Close()

	var secondSocket *websocket.Conn
	var secondPeer net.Conn
	select {
	case secondSocket = <-serverSockets:
	case <-time.After(time.Second):
		t.Fatal("relay did not establish a replacement WSS transport")
	}
	select {
	case secondPeer = <-tcpPeers:
	case <-time.After(time.Second):
		t.Fatal("relay did not establish a replacement TCP transport")
	}
	defer secondSocket.Close()
	defer secondPeer.Close()
	if runner.count() != 1 {
		t.Fatalf("transport redial restarted WayVNC %d times", runner.count())
	}
	if result := manager.Stop(); result.Result != "applied" {
		t.Fatalf("stop result = %#v", result)
	}
}

// A short-lived child must release its cancellation watcher while the agent lives.
func TestRemoteDesktopCancellationWatcherEndsWithChild(t *testing.T) {
	ctx := t.Context()
	child, err := (execRemoteDesktopRunner{}).Start(ctx, "/bin/true", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	process := child.(*execRemoteDesktopProcess)
	watcherDone := make(chan struct{})
	go func() { process.watchCancellation(ctx); close(watcherDone) }()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-watcherDone:
	case <-time.After(time.Second):
		t.Fatal("child exit left cancellation watcher blocked")
	}
	if ctx.Err() != nil {
		t.Fatal("watcher required cancellation of the agent context")
	}
}

func TestRemoteDesktopRetriesFailedConfigRemoval(t *testing.T) {
	for _, cleanup := range []string{"stop", "relay"} {
		t.Run(cleanup, func(t *testing.T) {
			dir := privateRemoteDesktopTempDir(t)
			manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{StateDir: dir, InstanceURL: "https://control.example"})
			if err != nil {
				t.Fatal(err)
			}
			desired := testRemoteDesktopDesired(time.Now(), "start")
			path, err := manager.writeConfig(&desired)
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Dir(path)
			if err := os.Chmod(parent, 0500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
			if cleanup == "stop" {
				if result := manager.Stop(); result.Result != "failed" {
					t.Fatalf("expected cleanup failure: %+v", result)
				}
			} else {
				_, config, _, _, _ := manager.takeRuntime()
				manager.runtime.mu.Lock()
				generation := manager.runtime.generation
				manager.runtime.mu.Unlock()
				manager.removeConfigForGeneration(generation, config)
			}
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if result := manager.Stop(); result.Result != "applied" {
				t.Fatalf("cleanup retry failed: %+v", result)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("private config remains: %v", err)
			}
			// Successful inactive Stop must keep its filesystem-free fast path.
			if err := os.Chmod(parent, 0500); err != nil {
				t.Fatal(err)
			}
			if result := manager.Stop(); result.Result != "applied" {
				t.Fatalf("inactive stop touched filesystem: %+v", result)
			}
		})
	}
}

type finalBytesConn struct{ net.Conn }

func (finalBytesConn) Read(buffer []byte) (int, error) { return copy(buffer, "final frame"), io.EOF }

func TestRemoteDesktopForwardsFinalBytesBeforeEOF(t *testing.T) {
	received := make(chan string, 1)
	socket := sessionTestConnection(t, func(connection *websocket.Conn) {
		kind, data, err := connection.ReadMessage()
		if err == nil && kind == websocket.BinaryMessage {
			received <- string(data)
		}
	})
	manager := &RemoteDesktopManager{options: RemoteDesktopManagerOptions{WaitTimeout: time.Second}}
	manager.rawToWebsocket(t.Context(), finalBytesConn{}, socket)
	select {
	case got := <-received:
		if got != "final frame" {
			t.Fatalf("final data=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("final bytes discarded")
	}
}
