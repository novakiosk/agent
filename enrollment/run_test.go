package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsreconcile"
)

func TestDesiredAckCanonicalSigningAndStrictSnapshotHash(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	category := "browser-navigation"
	ack := DesiredAck{
		Version: ProtocolVersion, Type: "desired.ack", Profile: ProvisionalIdentityProfile,
		SessionID: "session-1", DeviceID: identity.DeviceID, GroupID: "group-1", RevisionID: "revision-1", Revision: 1,
		Result: "failed", ObservedURL: "", ErrorCategory: &category, ObservedAt: "2026-08-24T12:00:00.000Z", Sequence: 7,
	}
	signature, err := encodeIdentitySignature(identity, DesiredAckCanonical(ack))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(identity.PublicIdentityRef, DesiredAckCanonical(ack), signature) {
		t.Fatal("valid desired ACK signature was rejected")
	}
	if !strings.Contains(string(DesiredAckCanonical(ack)), "type=ZGVzaXJlZC5hY2s") {
		t.Fatal("desired ACK canonical domain is missing")
	}
	changed := ack
	changed.ObservedAt = "2026-08-24T12:00:01.000Z"
	if VerifySignature(identity.PublicIdentityRef, DesiredAckCanonical(changed), signature) {
		t.Fatal("changed observedAt retained the original signature")
	}

	url := "https://EXAMPLE.TEST/presentation#screen"
	normalized, err := CanonicalPresentationURL(url)
	if err != nil || normalized != "https://example.test/presentation#screen" {
		t.Fatalf("normalized presentation URL = %q, %v", normalized, err)
	}
	if _, err := CanonicalPresentationURL("https://example.test/#"); err == nil {
		t.Fatal("empty trailing fragment was accepted")
	}
	if _, err := CanonicalPresentationURL("https://example.test/%zz"); err == nil {
		t.Fatal("invalid percent escape was accepted")
	}
	if _, err := CanonicalPresentationURL("https://example.test/%2F"); err != nil {
		t.Fatalf("valid percent escape was rejected: %v", err)
	}
	snapshot := DesiredSnapshot{
		Version: ProtocolVersion, Type: "desired.snapshot", SessionID: "session-1", DeviceID: identity.DeviceID,
		Desired: &DesiredContent{Type: "single-url-v1", GroupID: "group-1", RevisionID: "revision-1", Revision: 1, URL: normalized, PayloadHash: PresentationPayloadHash(normalized)},
	}
	if err := validateDesiredSnapshot(snapshot, "session-1", identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	badHash := snapshot
	content := *snapshot.Desired
	content.PayloadHash = strings.Repeat("0", 64)
	badHash.Desired = &content
	if err := validateDesiredSnapshot(badHash, "session-1", identity.DeviceID); err == nil {
		t.Fatal("snapshot with a mismatched payload hash was accepted")
	}
	if err := decodeStrict([]byte(`{"version":1,"type":"desired.snapshot","sessionId":"session-1","deviceId":"device","desired":null,"extra":true}`), &DesiredSnapshot{}); err == nil {
		t.Fatal("snapshot with an unknown field was accepted")
	}
}

func TestRunStateAndBrowserProfilePermissions(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentityAtomic(stateDir, identity); err != nil {
		t.Fatal(err)
	}
	state := State{
		Version: ProtocolVersion, Status: "Managed", InstanceURL: "https://control.example", EnrollmentID: "enrollment-1",
		DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1",
		SessionID: "session-1", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-24T12:00:00Z", AckSequence: 4,
		LastAckResult: "applied", LastRevisionID: "revision-1", LastRevision: 1, LastAppliedURL: "https://example.test/",
	}
	if err := SaveStateAtomic(stateDir, state); err != nil {
		t.Fatal(err)
	}
	stateInfo, err := os.Stat(StatePath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if got := stateInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode = %o, want 600", got)
	}
	directoryInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", got)
	}
	loaded, err := LoadState(stateDir)
	if err != nil || loaded.AckSequence != 4 || loaded.LastRevisionID != "revision-1" {
		t.Fatalf("persisted ACK state = %+v, %v", loaded, err)
	}

	profile := filepath.Join(t.TempDir(), "chromium-profile")
	if _, err := NewChromiumBrowser(context.Background(), ChromiumOptions{Binary: "/path/that/does/not/exist", UserDataDir: profile}); err == nil {
		t.Fatal("nonexistent Chromium binary unexpectedly started")
	}
	profileInfo, err := os.Stat(profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := profileInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("Chromium profile mode = %o, want 700", got)
	}
	unsafeProfile := filepath.Join(t.TempDir(), "unsafe-profile")
	if err := os.Mkdir(unsafeProfile, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChromiumBrowser(context.Background(), ChromiumOptions{Binary: "/path/that/does/not/exist", UserDataDir: unsafeProfile}); err == nil || !strings.Contains(err.Error(), "mode 0700") {
		t.Fatalf("non-private Chromium profile error = %v, want mode rejection", err)
	}
	targetProfile := filepath.Join(t.TempDir(), "target-profile")
	if err := os.Mkdir(targetProfile, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkProfile := filepath.Join(t.TempDir(), "symlink-profile")
	if err := os.Symlink(targetProfile, symlinkProfile); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChromiumBrowser(context.Background(), ChromiumOptions{Binary: "/path/that/does/not/exist", UserDataDir: symlinkProfile}); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlink Chromium profile error = %v, want directory-type rejection", err)
	}
	if _, err := NewChromiumBrowser(context.Background(), ChromiumOptions{Binary: "/path/that/does/not/exist", UserDataDir: profile, ExtraArgs: []string{"--remote-debugging-port=9222"}}); err == nil || !strings.Contains(err.Error(), "network Chromium debugging is not permitted") {
		t.Fatalf("network debugging argument error = %v, want debugging rejection", err)
	}
}

type runFixture struct {
	printerJobsHandler           func(*websocket.Conn, PrinterJobsReport) bool
	printerJobsProgress          chan State
	browserCommandAfterSecondAck *BrowserCommand
	t                            *testing.T
	state                        State
	identity                     Identity
	stateDir                     string
	handshakes                   atomic.Int32
	heartbeats                   chan int
	displayModes                 chan DisplayMode
	acks                         chan DesiredAck
	idleAcks                     chan IdleAck
	runtimeAcks                  chan RuntimeAck
	printerReports               chan PrinterReport
	printerAcks                  chan cupsreconcile.Ack
	remotePolls                  chan RemoteDesktopPoll
	browserCommandResults        chan BrowserCommandResult
	printerDesired               *cupsreconcile.Desired
	printerJobCommand            *PrinterJobCommand
	printerQueueCommand          *PrinterQueueCommand
	printerCommandResults        chan string
	dropPrinterResult            bool
	desired                      DesiredContent
	browserCommand               *BrowserCommand
	idle                         *IdleDesired
	runtime                      *RuntimeArtifact
	runtimeSequence              []*RuntimeArtifact
	runtimeStep                  atomic.Int32
	closeFirst                   bool
	closeAfterAck                bool
	closeAfterRuntimeAck         bool
	badAck                       bool
	nullDesired                  bool
	remoteDesktopV2              bool
	remotePollIntervalMs         int
}

func newRunFixture(t *testing.T, closeFirst, closeAfterAck bool, p256 ...bool) (*runFixture, Client, *testTLSServer) {
	t.Helper()
	stateDir := tempStateDir(t)
	identity, err := GenerateIdentity()
	if len(p256) > 0 && p256[0] {
		identity, err = CreateSoftwareIdentity(stateDir, "opaque:device-01")
	} else if err == nil {
		err = SaveIdentityAtomic(stateDir, identity)
	}
	if err != nil {
		t.Fatal(err)
	}
	fixture := &runFixture{t: t, identity: identity, heartbeats: make(chan int, 32), displayModes: make(chan DisplayMode, 32), acks: make(chan DesiredAck, 32), idleAcks: make(chan IdleAck, 32), runtimeAcks: make(chan RuntimeAck, 32), printerReports: make(chan PrinterReport, 32), printerAcks: make(chan cupsreconcile.Ack, 32), remotePolls: make(chan RemoteDesktopPoll, 32), browserCommandResults: make(chan BrowserCommandResult, 32), closeFirst: closeFirst, closeAfterAck: closeAfterAck}
	server, caPath := trustedTLSServer(t, http.HandlerFunc(fixture.serve))
	fixture.state = State{
		Version: ProtocolVersion, Status: "Managed", InstanceURL: server.URL, EnrollmentID: "enrollment-1",
		DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1",
		SessionID: "previous-session", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-24T12:00:00Z",
	}
	if err := SaveStateAtomic(stateDir, fixture.state); err != nil {
		t.Fatal(err)
	}
	fixture.stateDir = stateDir
	client := Client{StateDir: stateDir, CAPath: caPath, Now: func() time.Time { return time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC) }}
	return fixture, client, server
}

func (fixture *runFixture) serve(response http.ResponseWriter, request *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	connection, err := upgrader.Upgrade(response, request, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetReadLimit(MaxMessageBytes)
	handshake := int(fixture.handshakes.Add(1))
	accepted, err := fixture.handshake(connection, handshake)
	if err != nil {
		return
	}
	var pending []byte
	heartbeatNumber := 0
	for {
		var data []byte
		if pending != nil {
			data, pending = pending, nil
		} else {
			_, data, err = fixture.read(connection)
			if err != nil {
				return
			}
		}
		var heartbeat Heartbeat
		if err := decodeStrict(data, &heartbeat); err != nil || heartbeat.Type != "session.heartbeat" || !VerifySignature(fixture.identity.PublicIdentityRef, HeartbeatCanonical(heartbeat), heartbeat.Signature) {
			return
		}
		if fixture.printerJobsProgress != nil {
			state, err := LoadState(fixture.stateDir)
			if err != nil {
				fixture.t.Error(err)
				return
			}
			fixture.printerJobsProgress <- state
		}
		fixture.displayModes <- heartbeat.DisplayMode
		heartbeatNumber++
		heartbeats := heartbeatNumber
		fixture.heartbeats <- heartbeats
		var desired *DesiredContent
		if !fixture.nullDesired {
			content := fixture.desired
			if content.Type == "" {
				content = DesiredContent{Type: "single-url-v1", GroupID: "group-1", RevisionID: "revision-1", Revision: 1, URL: "https://example.test/presentation#screen"}
				content.PayloadHash = PresentationPayloadHash(content.URL)
			}
			desired = &content
		}
		runtime := fixture.runtime
		if len(fixture.runtimeSequence) > 0 {
			step := int(fixture.runtimeStep.Add(1)) - 1
			if step >= len(fixture.runtimeSequence) {
				step = len(fixture.runtimeSequence) - 1
			}
			runtime = fixture.runtimeSequence[step]
		}
		snapshot := DesiredSnapshot{Version: ProtocolVersion, Type: "desired.snapshot", SessionID: accepted.SessionID, DeviceID: fixture.state.DeviceID, Desired: desired, Idle: fixture.idle, Runtime: runtime, BrowserCommand: fixture.browserCommand, PrinterJobCommand: fixture.printerJobCommand, PrinterQueueCommand: fixture.printerQueueCommand}
		if fixture.remoteDesktopV2 {
			intervalMs := fixture.remotePollIntervalMs
			if intervalMs <= 0 {
				intervalMs = 1_000
			}
			snapshot.RemoteDesktopPoll = &RemoteDesktopPollPolicy{Enabled: true, IntervalMs: intervalMs}
		}
		if err := writeSessionMessage(connection, heartbeatAccepted{Version: ProtocolVersion, Type: "session.heartbeat.accepted", SessionID: accepted.SessionID, Sequence: heartbeat.Sequence}, time.Second); err != nil {
			return
		}
		if err := writeSessionMessage(connection, snapshot, time.Second); err != nil {
			return
		}
		if fixture.printerDesired != nil {
			printerDesired := *fixture.printerDesired
			printerDesired.SessionID = accepted.SessionID
			printerDesired.DeviceID = fixture.state.DeviceID
			if err := writeSessionMessage(connection, printerDesired, time.Second); err != nil {
				return
			}
		}
		if fixture.closeFirst && handshake == 1 {
			return
		}
		for {
			_, next, readErr := fixture.read(connection)
			if readErr != nil {
				return
			}
			var envelope struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(next, &envelope) != nil {
				return
			}
			switch envelope.Type {
			case "remote-desktop.poll":
				var poll RemoteDesktopPoll
				if decodeErr := decodeStrict(next, &poll); decodeErr != nil || poll.SessionID != accepted.SessionID || poll.DeviceID != fixture.state.DeviceID || !VerifySignature(fixture.identity.PublicIdentityRef, RemoteDesktopPollCanonical(poll), poll.Signature) {
					return
				}
				fixture.remotePolls <- poll
				if err := writeSessionMessage(connection, RemoteDesktopPollResult{Version: ProtocolVersion, Type: "remote-desktop.poll.result", SessionID: accepted.SessionID, DeviceID: fixture.state.DeviceID, Sequence: poll.Sequence, Enabled: true}, time.Second); err != nil {
					return
				}
			case "idle.desired.ack":
				var ack IdleAck
				if decodeErr := decodeStrict(next, &ack); decodeErr != nil || !VerifySignature(fixture.identity.PublicIdentityRef, IdleAckCanonical(ack), ack.Signature) {
					return
				}
				fixture.idleAcks <- ack
				if err := writeSessionMessage(connection, map[string]any{"version": ProtocolVersion, "type": "idle.desired.ack.accepted", "sessionId": ack.SessionID, "deviceId": ack.DeviceID, "idleScreenId": ack.IdleScreenID, "revisionId": ack.RevisionID, "payloadHash": ack.PayloadHash, "result": ack.Result, "sequence": ack.Sequence, "disposition": "accepted"}, time.Second); err != nil {
					return
				}
			case cupsreconcile.AckType:
				var ack cupsreconcile.Ack
				if decodeErr := decodeStrict(next, &ack); decodeErr != nil || !VerifySignature(fixture.identity.PublicIdentityRef, cupsreconcile.AckCanonical(ack), ack.Signature) {
					return
				}
				fixture.printerAcks <- ack
				if err := writeSessionMessage(connection, map[string]any{"version": 1, "type": "printer.desired.ack.accepted", "sessionId": ack.SessionID, "deviceId": ack.DeviceID, "desiredHash": ack.DesiredHash, "result": ack.Result, "sequence": ack.Sequence, "disposition": "accepted"}, time.Second); err != nil {
					return
				}
			case PrinterJobsType:
				var report PrinterJobsReport
				if err := decodeStrict(next, &report); err != nil || ValidatePrinterJobs(report, accepted.SessionID, fixture.state.DeviceID) != nil || !VerifySignature(fixture.identity.PublicIdentityRef, PrinterJobsCanonical(report), report.Signature) {
					fixture.t.Error("invalid signed printer jobs report")
					return
				}
				if fixture.printerJobsHandler == nil || !fixture.printerJobsHandler(connection, report) {
					return
				}
			case PrinterReportType:
				var report PrinterReport
				if decodeErr := decodeStrict(next, &report); decodeErr != nil || ValidatePrinterReport(report, accepted.SessionID, fixture.state.DeviceID) != nil || !VerifySignature(fixture.identity.PublicIdentityRef, PrinterReportCanonical(report), report.Signature) {
					return
				}
				fixture.printerReports <- report
				if err := writeSessionMessage(connection, PrinterReportAccepted{Version: ProtocolVersion, Type: "printer.report.accepted", SessionID: report.SessionID, DeviceID: report.DeviceID, ReportHash: report.ReportHash, Sequence: report.Sequence, Disposition: "accepted"}, time.Second); err != nil {
					return
				}
			case HostInventoryType:
				var report HostInventoryEnvelope
				if decodeErr := decodeStrict(next, &report); decodeErr != nil || validateHostInventoryEnvelope(report, accepted.SessionID, fixture.state.DeviceID) != nil || !VerifySignature(fixture.identity.PublicIdentityRef, HostInventoryCanonical(report), report.Signature) {
					return
				}
				if err := writeSessionMessage(connection, map[string]any{"version": ProtocolVersion, "type": "host.inventory.accepted", "sessionId": report.SessionID, "deviceId": report.DeviceID, "inventoryHash": report.InventoryHash, "sequence": report.Sequence, "disposition": "accepted"}, time.Second); err != nil {
					return
				}
			case "runtime.ack":
				var ack RuntimeAck
				if decodeErr := decodeStrict(next, &ack); decodeErr != nil || ack.Type != "runtime.ack" || !VerifySignature(fixture.identity.PublicIdentityRef, RuntimeAckCanonical(ack), ack.Signature) {
					return
				}
				fixture.runtimeAcks <- ack
				if fixture.closeAfterRuntimeAck && handshake == 1 {
					return
				}
				if err := writeSessionMessage(connection, map[string]any{"version": ProtocolVersion, "type": "runtime.ack.accepted", "sessionId": ack.SessionID, "deviceId": ack.DeviceID, "artifactRevision": ack.ArtifactRevision, "artifactHash": ack.ArtifactHash, "result": ack.Result, "sequence": ack.Sequence, "disposition": "accepted"}, time.Second); err != nil {
					return
				}
			case "desired.ack":
				var ack DesiredAck
				if decodeErr := decodeStrict(next, &ack); decodeErr != nil {
					return
				}
				fixture.acks <- ack
				if ack.Sequence == 2 && fixture.browserCommandAfterSecondAck != nil {
					fixture.browserCommand = fixture.browserCommandAfterSecondAck
				}
				if fixture.closeAfterAck && handshake == 1 {
					return
				}
				deviceID := ack.DeviceID
				if fixture.badAck && handshake == 1 {
					deviceID = "wrong-device"
				}
				if err := writeSessionMessage(connection, map[string]any{"version": ProtocolVersion, "type": "desired.ack.accepted", "sessionId": ack.SessionID, "deviceId": deviceID, "groupId": ack.GroupID, "revisionId": ack.RevisionID, "revision": ack.Revision, "result": ack.Result, "sequence": ack.Sequence, "disposition": "accepted"}, time.Second); err != nil {
					return
				}
			case "printer.job.command.result":
				var result PrinterJobCommandResult
				if decodeStrict(next, &result) != nil || !VerifySignature(fixture.identity.PublicIdentityRef, PrinterJobCommandResultCanonical(result), result.Signature) {
					return
				}
				fixture.printerCommandResults <- result.Result
				if fixture.dropPrinterResult && handshake == 1 {
					return
				}
				if writeSessionMessage(connection, PrinterJobCommandAccepted{Version: 1, Type: "printer.job.command.result.accepted", SessionID: result.SessionID, DeviceID: result.DeviceID, CommandID: result.CommandID, PayloadHash: result.PayloadHash, Sequence: result.Sequence, Disposition: "accepted"}, time.Second) != nil {
					return
				}
				fixture.printerJobCommand = nil
			case "printer.queue.command.result":
				var result PrinterQueueCommandResult
				if decodeStrict(next, &result) != nil || !VerifySignature(fixture.identity.PublicIdentityRef, PrinterQueueCommandResultCanonical(result), result.Signature) {
					return
				}
				fixture.printerCommandResults <- result.Result
				if fixture.dropPrinterResult && handshake == 1 {
					return
				}
				if writeSessionMessage(connection, PrinterQueueCommandAccepted{Version: 1, Type: "printer.queue.command.result.accepted", SessionID: result.SessionID, DeviceID: result.DeviceID, CommandID: result.CommandID, PayloadHash: result.PayloadHash, Sequence: result.Sequence, Disposition: "accepted"}, time.Second) != nil {
					return
				}
				fixture.printerQueueCommand = nil
			case BrowserCommandResultType:
				var result BrowserCommandResult
				if decodeErr := decodeStrict(next, &result); decodeErr != nil || !VerifySignature(fixture.identity.PublicIdentityRef, BrowserCommandResultCanonical(result), result.Signature) {
					return
				}
				if err := writeSessionMessage(connection, map[string]any{"version": ProtocolVersion, "type": "browser.command.result.accepted", "sessionId": result.SessionID, "deviceId": result.DeviceID, "commandId": result.CommandID, "action": result.Action, "sequence": result.Sequence, "disposition": "accepted"}, time.Second); err != nil {
					return
				}
				fixture.browserCommandResults <- result
				fixture.browserCommand = nil
			case "session.heartbeat":
				pending = next
			default:
				return
			}
			if pending != nil {
				break
			}
		}
	}
}

func (fixture *runFixture) read(connection *websocket.Conn) (int, []byte, error) {
	fixture.t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, nil, err
	}
	messageType, data, err := connection.ReadMessage()
	return messageType, data, err
}

func (fixture *runFixture) handshake(connection *websocket.Conn, number int) (sessionAccepted, error) {
	_, data, err := fixture.read(connection)
	if err != nil {
		return sessionAccepted{}, err
	}
	var hello struct {
		Version           int      `json:"version"`
		Type              string   `json:"type"`
		EnrollmentID      string   `json:"enrollmentId"`
		DeviceID          string   `json:"deviceId"`
		PublicIdentityRef string   `json:"publicIdentityRef"`
		Capabilities      []string `json:"capabilities,omitempty"`
	}
	if err := decodeStrict(data, &hello); err != nil || hello.Type != "session.hello" || hello.EnrollmentID != fixture.state.EnrollmentID || hello.DeviceID != fixture.state.DeviceID || hello.PublicIdentityRef != fixture.identity.PublicIdentityRef {
		return sessionAccepted{}, fmt.Errorf("invalid session hello")
	}
	if fixture.printerDesired != nil && !slices.Contains(hello.Capabilities, cupsreconcile.Capability) {
		return sessionAccepted{}, fmt.Errorf("printer reconcile capability missing")
	}
	sessionID := fmt.Sprintf("session-%d", number)
	challenge := sessionChallenge{Version: ProtocolVersion, Type: "session.challenge", Profile: fixture.identity.Profile(), SessionID: sessionID, ChallengeID: "challenge-" + fmt.Sprint(number), EnrollmentID: fixture.state.EnrollmentID, IdentityBindingID: fixture.state.IdentityBindingID, DeviceID: fixture.state.DeviceID, PublicIdentityRef: fixture.identity.PublicIdentityRef, Nonce: "nonce-" + fmt.Sprint(number), Audience: fixture.state.InstanceURL, ExpiresAt: "2099-01-01T00:00:00Z"}
	if err := writeSessionMessage(connection, challenge, time.Second); err != nil {
		return sessionAccepted{}, err
	}
	_, data, err = fixture.read(connection)
	if err != nil {
		return sessionAccepted{}, err
	}
	var response ChallengeResponse
	if err := decodeStrict(data, &response); err != nil || response.Type != "session.challenge.response" || !VerifySignature(fixture.identity.PublicIdentityRef, ChallengeCanonical(response), response.Signature) {
		return sessionAccepted{}, fmt.Errorf("invalid challenge response")
	}
	accepted := sessionAccepted{Version: ProtocolVersion, Type: "session.accepted", Profile: fixture.identity.Profile(), SessionID: sessionID, EnrollmentID: fixture.state.EnrollmentID, IdentityBindingID: fixture.state.IdentityBindingID, DeviceID: fixture.state.DeviceID}
	if err := writeSessionMessage(connection, accepted, time.Second); err != nil {
		return sessionAccepted{}, err
	}
	return accepted, nil
}

type fakeRuntimeApplier struct {
	calls    atomic.Int32
	failures atomic.Int32
	failHash string
}

func (applier *fakeRuntimeApplier) Apply(_ context.Context, artifact RuntimeArtifact) error {
	applier.calls.Add(1)
	if err := ValidateRuntimeArtifact(artifact); err != nil {
		return err
	}
	if applier.failures.Load() > 0 && (applier.failHash == "" || applier.failHash == artifact.ArtifactHash) {
		applier.failures.Add(-1)
		return errors.New("injected runtime reload failure")
	}
	return nil
}

func runtimeRunFixtureArtifact() *RuntimeArtifact {
	artifact := &RuntimeArtifact{
		Version: ProtocolVersion, Type: "runtime.config", Status: "ready", ArtifactRevision: "0-runtime-fixture",
		Sway:     &RuntimeComponent{Revision: 0, SourceRevision: 0, Source: "global", Mode: "raw", Text: "# fixture\n# Raw Sway expert configuration\n"},
		NOVAKeys: &RuntimeComponent{Revision: 0, SourceRevision: 0, Source: "global", Mode: "simple", Text: "show_language_switcher = true\ndark_mode = false\n"},
	}
	artifact.ArtifactHash = RuntimeArtifactHash(*artifact)
	return artifact
}

func runtimeDirectBrowserFixtureArtifact(kiosk bool) *RuntimeArtifact {
	artifact := runtimeRunFixtureArtifact()
	artifact.Sway.Mode = "simple"
	artifact.Sway.Text = "# Chromium is started and navigated by novakiosk-agent (direct-chromium-v1)\n# Presentation target: \"{{presentation_url}}\"\n"
	artifact.Browser = &RuntimeBrowserManagement{Version: 1, Type: "direct-chromium-v1", Kiosk: kiosk}
	artifact.ArtifactRevision = "0-direct-runtime-fixture"
	artifact.ArtifactHash = RuntimeArtifactHash(*artifact)
	return artifact
}

type lifecycleBrowser struct {
	*FakeBrowser
	closes atomic.Int32
}

func (browser *lifecycleBrowser) Close() error {
	browser.closes.Add(1)
	return nil
}

type mismatchedZoomBrowser struct{ *FakeBrowser }

func (browser *mismatchedZoomBrowser) SetZoom(ctx context.Context, percent int) (string, int, error) {
	observedURL, _, err := browser.FakeBrowser.SetZoom(ctx, percent)
	if err != nil {
		return observedURL, 0, err
	}
	return observedURL, percent + 1, nil
}

func browserCommandFixture(action string, zoom *int) *BrowserCommand {
	command := &BrowserCommand{
		Version: ProtocolVersion, Type: BrowserCommandType, Profile: ProvisionalIdentityProfile,
		CommandID: "22222222-2222-4222-8222-222222222222", Action: action, ZoomPercent: zoom,
		IssuedAt: "2026-08-24T11:59:00Z", ExpiresAt: "2026-08-24T12:14:00Z",
	}
	command.PayloadHash = BrowserCommandHash(*command)
	return command
}

type orderedRuntimeApplier struct{ events chan<- string }

func (applier orderedRuntimeApplier) Apply(context.Context, RuntimeArtifact) error {
	applier.events <- "runtime"
	return nil
}

type orderedIdleRuntime struct{ events chan<- string }

func (runtime orderedIdleRuntime) Apply(context.Context, *IdleDesired) error {
	runtime.events <- "idle"
	return nil
}
func (orderedIdleRuntime) Close() error { return nil }

type orderedBrowser struct {
	*FakeBrowser
	events chan<- string
}

func (browser *orderedBrowser) Navigate(ctx context.Context, target string) (string, error) {
	browser.events <- "navigate"
	return browser.FakeBrowser.Navigate(ctx, target)
}

func waitForRuntimeAck(t *testing.T, fixture *runFixture, result <-chan error, expectedSequence uint64) RuntimeAck {
	t.Helper()
	select {
	case ack := <-fixture.runtimeAcks:
		if ack.Sequence != expectedSequence {
			t.Fatalf("runtime ACK sequence = %d, want %d", ack.Sequence, expectedSequence)
		}
		return ack
	case err := <-result:
		t.Fatalf("managed run stopped before runtime ACK: %v", err)
		return RuntimeAck{}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for runtime ACK")
		return RuntimeAck{}
	}
}

func TestRunSwayRuntimeAppliesOnceAndDoesNotACKRepeatSnapshots(t *testing.T) {
	for _, p256 := range []bool{false, true} {
		t.Run(fmt.Sprint(p256), func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false, p256)
			fixture.runtime = runtimeRunFixtureArtifact()
			applier := &fakeRuntimeApplier{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- client.Run(ctx, RunOptions{RuntimeMode: "sway", RuntimeApplier: applier, HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond})
			}()
			ack := waitForRuntimeAck(t, fixture, result, 1)
			if ack.Result != "applied" || ack.ErrorCategory != nil {
				t.Fatalf("runtime ACK = %+v", ack)
			}
			select {
			case <-fixture.heartbeats:
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for a repeat heartbeat")
			}
			select {
			case duplicate := <-fixture.runtimeAcks:
				t.Fatalf("accepted runtime artifact was ACKed again: %+v", duplicate)
			case <-time.After(100 * time.Millisecond):
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("Sway run error = %v", err)
			}
			if got := applier.calls.Load(); got != 1 {
				t.Fatalf("runtime apply calls = %d, want one", got)
			}

		})
	}
}

func TestRunStartsPrimaryKioskBrowserBeforeIdleRuntime(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.runtime = runtimeDirectBrowserFixtureArtifact(true)
	idle := testIdleDesired(t)
	fixture.idle = &idle
	client.IdleScreenSupported = true
	events := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{
			RuntimeMode: "sway", RuntimeApplier: orderedRuntimeApplier{events: events}, IdleRuntime: orderedIdleRuntime{events: events},
			HeartbeatInterval: time.Hour, ReconnectDelay: time.Millisecond,
			BrowserFactory: func(context.Context, string) (Browser, error) {
				events <- "browser"
				return &orderedBrowser{FakeBrowser: NewFakeBrowser(nil), events: events}, nil
			},
		})
	}()
	select {
	case ack := <-fixture.idleAcks:
		if ack.Result != "applied" {
			t.Fatalf("idle ACK = %+v", ack)
		}
	case err := <-result:
		t.Fatalf("managed run stopped before idle ACK: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for idle ACK")
	}
	want := []string{"runtime", "browser", "navigate", "idle"}
	got := []string{<-events, <-events, <-events, <-events}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("startup order = %#v, want %#v", got, want)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("managed run error = %v", err)
	}
}

func TestRunSwayRuntimeReplaysACKAfterResponseLossWithoutReapply(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.runtime = runtimeRunFixtureArtifact()
	fixture.closeAfterRuntimeAck = true
	applier := &fakeRuntimeApplier{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{RuntimeMode: "sway", RuntimeApplier: applier, HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond})
	}()
	first := waitForRuntimeAck(t, fixture, result, 1)
	if first.Result != "applied" {
		t.Fatalf("first runtime ACK = %+v", first)
	}
	second := waitForRuntimeAck(t, fixture, result, 2)
	if second.Result != "applied" {
		t.Fatalf("replayed runtime ACK = %+v", second)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Sway reconnect error = %v", err)
	}
	if got := applier.calls.Load(); got != 1 {
		t.Fatalf("runtime apply calls after response loss = %d, want one", got)
	}
	if got := fixture.handshakes.Load(); got < 2 {
		t.Fatalf("handshakes after response loss = %d, want reconnect", got)
	}
}

func TestRunSwayRuntimeRetriesFailedApply(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.runtime = runtimeRunFixtureArtifact()
	applier := &fakeRuntimeApplier{}
	applier.failures.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{RuntimeMode: "sway", RuntimeApplier: applier, HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond})
	}()
	first := waitForRuntimeAck(t, fixture, result, 1)
	if first.Result != "failed" || first.ErrorCategory == nil || *first.ErrorCategory != "runtime-reload" {
		t.Fatalf("failed runtime ACK = %+v", first)
	}
	second := waitForRuntimeAck(t, fixture, result, 2)
	if second.Result != "applied" {
		t.Fatalf("retry runtime ACK = %+v", second)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Sway retry error = %v", err)
	}
	if got := applier.calls.Load(); got != 2 {
		t.Fatalf("runtime apply calls = %d, want two", got)
	}
}

func TestRunSwayManagedBrowserStartFailureACKsAndRecovers(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.runtime = runtimeDirectBrowserFixtureArtifact(true)
	var starts atomic.Int32
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{
			RuntimeMode: "sway", RuntimeApplier: &fakeRuntimeApplier{}, HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond,
			BrowserFactory: func(context.Context, string) (Browser, error) {
				if starts.Add(1) == 1 {
					return nil, errors.New("Wayland display socket is unavailable")
				}
				return browser, nil
			},
		})
	}()
	waitForRuntimeAck(t, fixture, result, 1)
	var failed, applied DesiredAck
	select {
	case failed = <-fixture.acks:
	case err := <-result:
		t.Fatalf("managed run stopped before start-failure ACK: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for browser start-failure ACK")
	}
	select {
	case applied = <-fixture.acks:
		cancel()
	case err := <-result:
		t.Fatalf("managed run stopped before browser recovery ACK: %v", err)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for browser recovery ACK")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("managed browser recovery run error = %v", err)
	}
	if failed.Result != "failed" || failed.ErrorCategory == nil || *failed.ErrorCategory != "browser-unavailable" || failed.ObservedURL != "" {
		t.Fatalf("start-failure ACK = %+v", failed)
	}
	if applied.Result != "applied" || applied.ErrorCategory != nil || applied.ObservedURL != "https://example.test/presentation#screen" {
		t.Fatalf("recovery ACK = %+v", applied)
	}
	if starts.Load() < 2 {
		t.Fatalf("browser starts = %d, want recovery attempt", starts.Load())
	}
	browser.Mu.Lock()
	if !reflect.DeepEqual(browser.History, []string{"https://example.test/presentation#screen"}) {
		t.Fatalf("recovery browser history = %#v", browser.History)
	}
	browser.Mu.Unlock()
}

func TestRunBrowserCommandRejectsMismatchedZoomObservation(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	zoom := 125
	fixture.browserCommand = browserCommandFixture("set-zoom", &zoom)
	if err := fixture.browserCommand.Validate(client.now(), false); err != nil {
		t.Fatalf("fixture browser command is invalid: %v", err)
	}
	browser := &mismatchedZoomBrowser{FakeBrowser: NewFakeBrowser(nil)}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{
			HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond,
			BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil },
		})
	}()
	select {
	case commandResult := <-fixture.browserCommandResults:
		if commandResult.Result != "failed" || commandResult.ErrorCategory == nil || *commandResult.ErrorCategory != "browser-zoom" {
			t.Fatalf("mismatched zoom result = %+v", commandResult)
		}
		if commandResult.ZoomPercent != nil {
			t.Fatalf("mismatched zoom result reported accepted zoom = %v", *commandResult.ZoomPercent)
		}
		cancel()
	case err := <-result:
		cancel()
		t.Fatalf("Run stopped before browser command result: %v", err)
	case <-time.After(3 * time.Second):
		cancel()
		state, stateErr := LoadState(client.StateDir)
		t.Fatalf("timed out waiting for browser command result (state=%+v err=%v heartbeats=%d)", state, stateErr, len(fixture.heartbeats))
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	state, err := LoadState(client.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastBrowserCommandZoom != nil {
		t.Fatalf("persisted mismatched zoom = %v", *state.LastBrowserCommandZoom)
	}
}

func TestRunBrowserRestartFailureRecoversOnLaterHeartbeat(t *testing.T) {
	for _, mode := range []string{"browser", "sway"} {
		t.Run(mode, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			if mode == "sway" {
				fixture.runtime = runtimeDirectBrowserFixtureArtifact(false)
				fixture.runtime.Browser.KioskPrinting = true
				fixture.runtime.ArtifactHash = RuntimeArtifactHash(*fixture.runtime)
			}
			fixture.browserCommand = browserCommandFixture("restart-browser", nil)
			if err := fixture.browserCommand.Validate(client.now(), false); err != nil {
				t.Fatalf("fixture browser command is invalid: %v", err)
			}
			oldBrowser := &lifecycleBrowser{FakeBrowser: NewFakeBrowser(nil)}
			newBrowser := &lifecycleBrowser{FakeBrowser: NewFakeBrowser(nil)}
			var starts atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				result <- client.Run(ctx, RunOptions{RuntimeMode: mode, RuntimeApplier: &fakeRuntimeApplier{},
					HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond,
					BrowserFactory: func(context.Context, string) (Browser, error) {
						switch starts.Add(1) {
						case 1:
							return oldBrowser, nil
						case 2:
							return nil, errors.New("transient Chromium startup failure")
						default:
							return newBrowser, nil
						}
					},
				})
			}()
			select {
			case commandResult := <-fixture.browserCommandResults:
				if commandResult.Result != "failed" || commandResult.ErrorCategory == nil || *commandResult.ErrorCategory != "browser-restart" {
					t.Fatalf("restart failure result = %+v", commandResult)
				}
			case err := <-result:
				cancel()
				t.Fatalf("Run stopped before restart failure result: %v", err)
			case <-time.After(3 * time.Second):
				cancel()
				state, stateErr := LoadState(client.StateDir)
				t.Fatalf("timed out waiting for restart failure result (state=%+v err=%v heartbeats=%d starts=%d)", state, stateErr, len(fixture.heartbeats), starts.Load())
			}
			select {
			case ack := <-fixture.acks:
				if ack.Result != "failed" {
					t.Fatalf("missing unavailable observation: %+v", ack)
				}
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("missing unavailable ACK")
			}
			select {
			case ack := <-fixture.acks:
				if ack.Result != "applied" || ack.ObservedURL != "https://example.test/presentation#screen" {
					t.Fatalf("recovery desired ACK = %+v", ack)
				}
				cancel()
			case err := <-result:
				cancel()
				t.Fatalf("Run stopped before recovery desired ACK: %v", err)
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("timed out waiting for recovery desired ACK")
			}
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run error = %v", err)
			}
			if got := oldBrowser.closes.Load(); got < 1 {
				t.Fatalf("old browser close count = %d, want restart close", got)
			}
			if got := starts.Load(); got < 3 {
				t.Fatalf("browser starts = %d, want failed restart and recovery", got)
			}
			newBrowser.Mu.Lock()
			defer newBrowser.Mu.Unlock()
			if !reflect.DeepEqual(newBrowser.History, []string{"https://example.test/presentation#screen"}) {
				t.Fatalf("recovered browser history = %#v", newBrowser.History)
			}
		})
	}
}

func TestRunSwayFailedRuntimeTransitionKeepsWorkingBrowser(t *testing.T) {
	tests := []struct {
		name string
		next func() *RuntimeArtifact
	}{
		{name: "direct-to-raw", next: runtimeRunFixtureArtifact},
		{name: "direct-to-direct", next: func() *RuntimeArtifact { return runtimeDirectBrowserFixtureArtifact(false) }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			first := runtimeDirectBrowserFixtureArtifact(true)
			next := testCase.next()
			fixture.runtimeSequence = []*RuntimeArtifact{first, next}
			applier := &fakeRuntimeApplier{failHash: next.ArtifactHash}
			// Keep the transition failing for the duration of this test. This
			// lets us observe that no lifecycle action occurs before a later
			// successful runtime apply.
			applier.failures.Store(1000)
			oldBrowser := &lifecycleBrowser{FakeBrowser: NewFakeBrowser(nil)}
			newBrowser := &lifecycleBrowser{FakeBrowser: NewFakeBrowser(nil)}
			var starts atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				result <- client.Run(ctx, RunOptions{
					RuntimeMode: "sway", RuntimeApplier: applier,
					HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond,
					BrowserFactory: func(context.Context, string) (Browser, error) {
						if starts.Add(1) == 1 {
							return oldBrowser, nil
						}
						return newBrowser, nil
					},
				})
			}()
			defer cancel()

			firstRuntime := waitForRuntimeAck(t, fixture, result, 1)
			if firstRuntime.Result != "applied" {
				t.Fatalf("initial runtime ACK = %+v", firstRuntime)
			}
			select {
			case desired := <-fixture.acks:
				if desired.Result != "applied" {
					t.Fatalf("initial desired ACK = %+v", desired)
				}
			case err := <-result:
				t.Fatalf("managed run stopped before initial desired ACK: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for initial desired ACK")
			}

			failedRuntime := waitForRuntimeAck(t, fixture, result, 2)
			if failedRuntime.Result != "failed" {
				t.Fatalf("failed transition runtime ACK = %+v", failedRuntime)
			}
			// Allow the ACK acceptance and several failed retries to complete.
			// The old implementation would close oldBrowser here and either
			// start newBrowser or emit an unsupported desired ACK.
			time.Sleep(100 * time.Millisecond)
			if got := oldBrowser.closes.Load(); got != 0 {
				t.Fatalf("old browser close count after failed %s transition = %d", testCase.name, got)
			}
			if got := starts.Load(); got != 1 {
				t.Fatalf("browser starts after failed %s transition = %d, want 1", testCase.name, got)
			}
			select {
			case desired := <-fixture.acks:
				t.Fatalf("unexpected desired ACK after failed %s transition: %+v", testCase.name, desired)
			default:
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("failed %s transition run error = %v", testCase.name, err)
			}
		})
	}
}

func TestRunKeepsOneAuthenticatedSocketAcrossHeartbeats(t *testing.T) {
	for _, p256 := range []bool{false, true} {
		t.Run(fmt.Sprint(p256), func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false, p256)
			browser := NewFakeBrowser(nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- client.Run(ctx, RunOptions{HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
			}()
			select {
			case count := <-fixture.heartbeats:
				if count != 1 {
					t.Fatalf("first heartbeat number = %d", count)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for first heartbeat")
			}
			select {
			case ack := <-fixture.acks:
				if ack.Result != "applied" {
					t.Fatalf("first ACK = %+v", ack)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for first ACK")
			}
			select {
			case count := <-fixture.heartbeats:
				if count != 2 {
					t.Fatalf("second heartbeat number = %d", count)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for second heartbeat")
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				state, err := LoadState(client.StateDir)
				if err == nil && state.HeartbeatSequence >= 3 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("heartbeat state was not persisted: %+v (%v)", state, err)
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run error = %v, want context cancellation", err)
			}
			if got := fixture.handshakes.Load(); got != 1 {
				t.Fatalf("handshakes = %d, want one persistent session", got)
			}
			browser.Mu.Lock()
			history := append([]string(nil), browser.History...)
			browser.Mu.Unlock()
			if len(history) != 1 {
				t.Fatalf("browser navigations = %d, want one", len(history))
			}
			select {
			case extra := <-fixture.acks:
				t.Fatalf("same applied revision was ACKed again: %+v", extra)
			default:
			}

		})
	}
}

func TestRunInterleavesRemotePollsWithoutStarvingHeartbeat(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.remoteDesktopV2 = true
	fixture.remotePollIntervalMs = 1_500
	// Scheduling uses the injected clock for both deadlines and signed
	// observations; this test needs it to advance between timer firings.
	client.Now = time.Now
	manager, err := NewRemoteDesktopManager(RemoteDesktopManagerOptions{
		StateDir: fixture.stateDir, InstanceURL: fixture.state.InstanceURL,
		Environment: []string{"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-1"},
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.RemoteDesktopSupported = true
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{
			HeartbeatInterval: 4200 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond,
			BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil },
			RemoteDesktop:  manager,
		})
	}()
	select {
	case count := <-fixture.heartbeats:
		if count != 1 {
			t.Fatalf("first heartbeat number = %d", count)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first heartbeat")
	}
	select {
	case ack := <-fixture.acks:
		if ack.Result != "applied" {
			t.Fatalf("initial desired ACK = %+v", ack)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial desired ACK")
	}
	var pollTimes []time.Time
	for sequence := uint64(1); sequence <= 2; sequence++ {
		select {
		case poll := <-fixture.remotePolls:
			if poll.Sequence != sequence {
				t.Fatalf("remote poll sequence = %d, want %d", poll.Sequence, sequence)
			}
			observedAt, parseErr := time.Parse(time.RFC3339Nano, poll.ObservedAt)
			if parseErr != nil {
				t.Fatalf("remote poll observedAt = %q: %v", poll.ObservedAt, parseErr)
			}
			pollTimes = append(pollTimes, observedAt)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for remote poll %d", sequence)
		}
	}
	pollSpacing := pollTimes[1].Sub(pollTimes[0])
	if pollSpacing < 1250*time.Millisecond || pollSpacing > 1750*time.Millisecond {
		t.Fatalf("remote poll spacing = %s, want approximately negotiated 1.5s", pollSpacing)
	}
	select {
	case count := <-fixture.heartbeats:
		if count != 2 {
			t.Fatalf("scheduled heartbeat number = %d, want 2 after polls", count)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("scheduled heartbeat was starved by remote polls")
	}
	deadline := time.Now().Add(time.Second)
	for {
		state, stateErr := LoadState(client.StateDir)
		if stateErr == nil && state.HeartbeatSequence >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat state was not persisted: %+v (%v)", state, stateErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context cancellation", err)
	}
}

func TestRunSignsObservedDisplayModeOnEveryHeartbeat(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	var observations atomic.Int32
	defer cancel()
	go func() {
		result <- client.Run(ctx, RunOptions{
			HeartbeatInterval: 10 * time.Millisecond,
			ReconnectDelay:    5 * time.Millisecond,
			BrowserFactory:    func(context.Context, string) (Browser, error) { return browser, nil },
			DisplayModeObserver: func() DisplayMode {
				if observations.Add(1) == 1 {
					return DisplayModeHeadless
				}
				return DisplayModePhysical
			},
		})
	}()
	for _, want := range []DisplayMode{DisplayModeHeadless, DisplayModePhysical} {
		select {
		case mode := <-fixture.displayModes:
			if mode != want {
				t.Fatalf("heartbeat display mode = %q, want %q", mode, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s heartbeat", want)
		}
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context cancellation", err)
	}
}

func TestRunRotatesPlaylistInOrderAndSignsObservedURL(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	items := []PlaylistItem{
		{Label: "Screen 1", URL: "https://example.test/one", DurationSeconds: 5},
		{Label: "Screen 2", URL: "https://example.test/two", DurationSeconds: 5},
	}
	fixture.desired = DesiredContent{
		Type: "playlist-v1", GroupID: "group-1", RevisionID: "playlist-1", Revision: 1,
		PayloadHash: PresentationPlaylistPayloadHash(items), Items: items,
	}
	var ticks atomic.Int64
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	client.Now = func() time.Time {
		// Advance the injected clock enough on each observation to exercise
		// timed rotation without a five-second wall-clock test.
		return base.Add(time.Duration(ticks.Add(1)) * 10 * time.Second)
	}
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{HeartbeatInterval: time.Hour, ReconnectDelay: time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
	}()
	acks := make([]DesiredAck, 0, 3)
	for len(acks) < 3 {
		select {
		case ack := <-fixture.acks:
			acks = append(acks, ack)
		case err := <-result:
			t.Fatalf("playlist run stopped before rotations: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for playlist ACKs")
		}
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("playlist run error = %v", err)
	}
	wantURLs := []string{items[0].URL, items[1].URL, items[0].URL}
	for index, ack := range acks {
		if ack.Result != "applied" || ack.ErrorCategory != nil || ack.ObservedURL != wantURLs[index] {
			t.Fatalf("playlist ACK[%d] = %+v, want applied %s", index, ack, wantURLs[index])
		}
		if !VerifySignature(fixture.identity.PublicIdentityRef, DesiredAckCanonical(ack), ack.Signature) {
			t.Fatalf("playlist ACK[%d] signature was invalid", index)
		}
	}
	browser.Mu.Lock()
	history := append([]string(nil), browser.History...)
	browser.Mu.Unlock()
	if !reflect.DeepEqual(history, wantURLs) {
		t.Fatalf("playlist browser history = %#v, want %#v", history, wantURLs)
	}
}

func TestPlaylistNextDeadlineUsesCurrentItemDuration(t *testing.T) {
	client := Client{Now: func() time.Time { return time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC) }}
	snapshot := DesiredSnapshot{Desired: &DesiredContent{Type: "playlist-v1", Items: []PlaylistItem{{URL: "https://example.test/one", DurationSeconds: 3}, {URL: "https://example.test/two", DurationSeconds: 11}}}}
	if got, want := client.playlistNextDeadline(snapshot, 1), time.Date(2026, 8, 24, 12, 0, 11, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("playlist deadline = %s, want %s", got, want)
	}
	if got := client.playlistNextDeadline(snapshot, -1); !got.IsZero() {
		t.Fatalf("invalid playlist index deadline = %s, want zero", got)
	}
}

func TestRunRetriesFailedNavigationOnSameSession(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	var attempts atomic.Int32
	browser := NewFakeBrowser(func(url string) (string, error) {
		if attempts.Add(1) == 1 {
			return "", errors.New("navigation failed")
		}
		return url, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
	}()
	var first, second DesiredAck
	select {
	case first = <-fixture.acks:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for failed ACK")
	}
	select {
	case second = <-fixture.acks:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for retry ACK")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if first.Result != "failed" || first.ErrorCategory == nil || *first.ErrorCategory != "browser-navigation" || first.Sequence != 1 {
		t.Fatalf("first ACK = %+v", first)
	}
	if second.Result != "applied" || second.ErrorCategory != nil || second.Sequence != 2 {
		t.Fatalf("second ACK = %+v", second)
	}
	browser.Mu.Lock()
	if len(browser.History) != 2 {
		t.Fatalf("browser navigation count = %d, want retry", len(browser.History))
	}
	browser.Mu.Unlock()
}

func TestRunFreshBrowserDoesNotTrustPersistedAppliedEvidence(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	state, err := LoadState(client.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.LastAckResult = "applied"
	state.LastRevisionID = "revision-1"
	state.LastRevision = 1
	state.LastAppliedURL = "https://example.test/presentation#screen"
	if err := SaveStateAtomic(client.StateDir, state); err != nil {
		t.Fatal(err)
	}
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
	}()
	select {
	case <-fixture.acks:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for fresh-browser ACK")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	browser.Mu.Lock()
	if len(browser.History) != 1 {
		t.Fatalf("fresh browser navigations = %d, want one", len(browser.History))
	}
	browser.Mu.Unlock()
}

func TestRunRejectsMismatchedAcceptedEnvelope(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.badAck = true
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx, RunOptions{HeartbeatInterval: time.Millisecond, ReconnectDelay: time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
	}()
	for range 2 {
		select {
		case <-fixture.acks:
		case <-ctx.Done():
			t.Fatal("missing retry after mismatched ACK")
		}
	}
	cancel()
	<-done
	if fixture.handshakes.Load() != 2 {
		t.Fatalf("handshakes = %d", fixture.handshakes.Load())
	}
	state, err := LoadState(fixture.stateDir)
	if err != nil || state.AckSequence < 2 {
		t.Fatalf("ACK retry state: %+v, %v", state, err)
	}
	browser.Mu.Lock()
	defer browser.Mu.Unlock()
	if len(browser.History) != 1 {
		t.Fatalf("navigations = %d", len(browser.History))
	}
}

func TestRunReconnectsAndReACKsWithoutNavigatingAfterDroppedResponse(t *testing.T) {
	fixture, client, _ := newRunFixture(t, true, false)
	browser := NewFakeBrowser(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for fixture.handshakes.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for reconnect handshake")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case ack := <-fixture.acks:
		cancel()
		if ack.Result != "applied" {
			t.Fatalf("reconnect ACK = %+v", ack)
		}
	case <-time.After(5 * time.Second):
		cancel()
		state, stateErr := LoadState(client.StateDir)
		browser.Mu.Lock()
		navigations := len(browser.History)
		browser.Mu.Unlock()
		t.Fatalf("timed out waiting for reconnect ACK (handshakes=%d, state=%+v/%v, navigations=%d, heartbeats=%d)", fixture.handshakes.Load(), state, stateErr, navigations, len(fixture.heartbeats))
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if got := fixture.handshakes.Load(); got != 2 {
		t.Fatalf("handshakes = %d, want reconnect", got)
	}
	browser.Mu.Lock()
	if len(browser.History) != 1 {
		t.Fatalf("browser navigations after dropped response = %d, want one", len(browser.History))
	}
	browser.Mu.Unlock()
}

func TestRunReturnsPermanentAuthorityRejectionWithoutRetry(t *testing.T) {
	var handshakes atomic.Int32
	server, caPath := trustedTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		connection, err := upgrader.Upgrade(response, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		handshakes.Add(1)
		_, _, _ = connection.ReadMessage()
		_ = writeSessionMessage(connection, map[string]any{"version": ProtocolVersion, "type": "session.rejected", "code": "IDENTITY_REVOKED"}, time.Second)
	}))
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "agent-state")
	state := State{Version: ProtocolVersion, Status: "Managed", InstanceURL: server.URL, EnrollmentID: "enrollment-1", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1", SessionID: "session-1", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-24T12:00:00Z"}
	if err := SaveIdentityAtomic(stateDir, identity); err != nil {
		t.Fatal(err)
	}
	if err := SaveStateAtomic(stateDir, state); err != nil {
		t.Fatal(err)
	}
	client := Client{StateDir: stateDir, CAPath: caPath, Now: func() time.Time { return time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC) }}
	browser := NewFakeBrowser(nil)
	err = client.Run(context.Background(), RunOptions{HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return browser, nil }})
	var protocolErr *SessionProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != "IDENTITY_REVOKED" {
		t.Fatalf("Run authority error = %v", err)
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("authority rejection handshakes = %d, want one", got)
	}
	loaded, loadErr := LoadState(stateDir)
	if loadErr != nil || loaded.Status != "Managed" {
		t.Fatalf("authority rejection changed state = %+v (%v)", loaded, loadErr)
	}
}

func TestPermanentSessionErrorIncludesHardwareEvidenceRejections(t *testing.T) {
	for _, code := range []string{
		"HOST_INVENTORY_INVALID", "HOST_INVENTORY_CONFLICT", "HOST_INVENTORY_OUT_OF_ORDER",
		"OPERATION_ACK_INVALID", "OPERATION_ACK_CONFLICT", "OPERATION_RESULT_INVALID", "OPERATION_RESULT_CONFLICT",
	} {
		if !permanentSessionError(&SessionProtocolError{Code: code}) {
			t.Fatalf("%s should stop reconnecting", code)
		}
	}
	if permanentSessionError(&SessionProtocolError{Code: "MESSAGE_INVALID"}) {
		t.Fatal("generic transport rejection should remain retryable")
	}
}

func (*fakeRuntimeApplier) Recover(context.Context) error   { return nil }
func (orderedRuntimeApplier) Recover(context.Context) error { return nil }

func validateHostInventoryEnvelope(report HostInventoryEnvelope, sessionID, deviceID string) error {
	if report.Version != ProtocolVersion || report.Type != HostInventoryType || !supportedIdentityProfile(report.Profile) || report.SessionID != sessionID || report.DeviceID != deviceID || report.Sequence == 0 || len(report.Signature) == 0 || len(report.Signature) > 256 {
		return fmt.Errorf("host inventory envelope is invalid")
	}
	if err := report.Inventory.Validate(); err != nil {
		return fmt.Errorf("host inventory is invalid")
	}
	hash, err := InventoryHash(report.Inventory)
	if err != nil || hash != report.InventoryHash || len(report.InventoryHash) != 64 {
		return fmt.Errorf("host inventory hash is invalid")
	}
	return nil
}

// Graphical connection changes must invalidate cached application without taking
// the authenticated session or independent printer inventory down.
func TestRunCompanionUnavailableThenReconnect(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false, true)
	fixture.runtime = runtimeRunFixtureArtifact()
	applier := &fakeRuntimeApplier{}
	applier.failures.Store(1000)
	var epoch atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.Run(ctx, RunOptions{RuntimeMode: "sway", RuntimeApplier: applier, RuntimeEpoch: func() string { return fmt.Sprint(epoch.Load()) }, PrinterReporter: bridgeReporter(), HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: 5 * time.Millisecond})
	}()
	first := waitForRuntimeAck(t, fixture, result, 1)
	if first.Result != "failed" {
		t.Fatalf("unavailable graphical apply: %+v", first)
	}
	select {
	case <-fixture.printerReports:
	case <-time.After(3 * time.Second):
		t.Fatal("printer reporting stopped without companion")
	}
	select {
	case <-fixture.heartbeats:
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat stopped without companion")
	}
	applier.failures.Store(0)
	epoch.Store(1)
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ack := <-fixture.runtimeAcks:
			if ack.Result == "applied" {
				goto applied
			}
		case err := <-result:
			t.Fatalf("run stopped: %v", err)
		case <-deadline:
			t.Fatal("pending graphical apply did not recover")
		}
	}
applied:
	before := applier.calls.Load()
	epoch.Store(2)
	deadline = time.After(3 * time.Second)
	for {
		select {
		case ack := <-fixture.runtimeAcks:
			if ack.Result == "applied" {
				goto reapplied
			}
		case err := <-result:
			t.Fatalf("run stopped: %v", err)
		case <-deadline:
			t.Fatal("reconnected companion reused stale apply")
		}
	}
reapplied:
	if applier.calls.Load() <= before {
		t.Fatal("new companion did not receive accepted desired")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
