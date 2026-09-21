package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsjob"
)

func testPrinterQueueCommand(action string) PrinterQueueCommand {
	command := PrinterQueueCommand{Version: ProtocolVersion, Type: "printer.queue.command", Profile: ProvisionalIdentityProfile, CommandID: "22222222-2222-4222-8222-222222222222", Action: action, AuthorityKind: "kiosk-usb", AuthorityID: "printer-1", QueueName: "USB_ZEBRA", IssuedAt: "2026-08-31T10:00:00Z", ExpiresAt: "2026-08-31T10:10:00Z"}
	command.PayloadHash = PrinterQueueCommandHash(command)
	return command
}

func TestPrinterQueueCommandCanonicalAndValidation(t *testing.T) {
	for _, action := range []string{cupsjob.ActionPause, cupsjob.ActionResume, cupsjob.ActionCancelAll, cupsjob.ActionDelete, cupsjob.ActionAddUSB} {
		command := testPrinterQueueCommand(action)
		if err := command.Validate(time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC), false); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(string(PrinterQueueCommandCanonical(command)), "queueName=VVNCX1pFQlJB") {
			t.Fatal("canonical queue field missing")
		}
	}
	command := testPrinterQueueCommand(cupsjob.ActionPause)
	command.QueueName = "../printer"
	command.PayloadHash = PrinterQueueCommandHash(command)
	if err := command.Validate(time.Now(), true); err == nil {
		t.Fatal("unsafe queue accepted")
	}
}

func TestPrinterQueueCommandFixtureMatchesCanonicalHash(t *testing.T) {
	data, err := os.ReadFile("../fixtures/printer-queue-command-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var command PrinterQueueCommand
	if err := json.Unmarshal(data, &command); err != nil {
		t.Fatal(err)
	}
	if command.PayloadHash != PrinterQueueCommandHash(command) {
		t.Fatalf("fixture hash = %s, canonical = %s", command.PayloadHash, PrinterQueueCommandHash(command))
	}
}

type countingPrinterQueueController struct {
	calls  atomic.Int32
	result cupsjob.Result
}

func (controller *countingPrinterQueueController) ControlQueue(context.Context, cupsjob.Request) (cupsjob.Result, error) {
	controller.calls.Add(1)
	return controller.result, nil
}

func applyPrinterQueueCommandPair(t *testing.T, client Client, state *State, identity Identity, command PrinterQueueCommand, controller PrinterQueueController, acknowledge bool) (PrinterQueueCommandResult, error) {
	t.Helper()
	received := make(chan PrinterQueueCommandResult, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		_, data, readErr := connection.ReadMessage()
		if readErr != nil {
			return
		}
		var result PrinterQueueCommandResult
		if decodeErr := decodeStrict(data, &result); decodeErr != nil {
			return
		}
		received <- result
		if acknowledge {
			_ = writeSessionMessage(connection, PrinterQueueCommandAccepted{Version: ProtocolVersion, Type: "printer.queue.command.result.accepted", SessionID: result.SessionID, DeviceID: result.DeviceID, CommandID: result.CommandID, PayloadHash: result.PayloadHash, Sequence: result.Sequence, Disposition: "accepted"}, time.Second)
		}
	}))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		return PrinterQueueCommandResult{}, err
	}
	defer connection.Close()
	snapshot := DesiredSnapshot{SessionID: "session-current", DeviceID: state.DeviceID, PrinterQueueCommand: &command}
	applyErr := client.applyPrinterQueueCommand(context.Background(), state, identity, connection, snapshot, controller)
	select {
	case result := <-received:
		return result, applyErr
	case <-time.After(2 * time.Second):
		return PrinterQueueCommandResult{}, applyErr
	}
}

func TestPrinterQueueCommandReplaysResultWithoutRepeatingCancelAll(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	state := State{Version: ProtocolVersion, Status: "Managed", InstanceURL: "https://control.example", EnrollmentID: "enrollment-1", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1", SessionID: "session-old", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-31T09:00:00Z", DeviceKind: DeviceKindKiosk}
	if err := SaveStateAtomic(stateDir, state); err != nil {
		t.Fatal(err)
	}
	command := testPrinterQueueCommand(cupsjob.ActionCancelAll)
	affected := uint64(3)
	controller := &countingPrinterQueueController{result: cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.QueueResultType, Profile: "kiosk", Action: cupsjob.ActionCancelAll, CommandHash: command.PayloadHash, QueueName: command.QueueName, Result: cupsjob.ResultApplied, AffectedJobs: &affected}}
	firstClient := Client{StateDir: stateDir, Now: func() time.Time { return time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC) }}
	first, firstErr := applyPrinterQueueCommandPair(t, firstClient, &state, identity, command, controller, false)
	if firstErr == nil || controller.calls.Load() != 1 || first.AffectedJobs == nil || *first.AffectedJobs != 3 {
		t.Fatalf("first apply: result=%+v err=%v calls=%d", first, firstErr, controller.calls.Load())
	}
	persisted, err := LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	secondClient := Client{StateDir: stateDir, Now: func() time.Time { return time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC) }}
	second, secondErr := applyPrinterQueueCommandPair(t, secondClient, &persisted, identity, command, controller, true)
	if secondErr != nil || controller.calls.Load() != 1 || second.ObservedAt != first.ObservedAt || second.AffectedJobs == nil || *second.AffectedJobs != 3 {
		t.Fatalf("replay: result=%+v err=%v calls=%d", second, secondErr, controller.calls.Load())
	}
	finalState, err := LoadState(stateDir)
	if err != nil || !finalState.LastPrinterQueueCommandAccepted {
		t.Fatalf("final state: %+v err=%v", finalState, err)
	}
}

type durableQueueController struct {
	calls       int
	jobs        []string
	canceled    []string
	afterEffect func()
}

func (c *durableQueueController) ControlQueue(_ context.Context, r cupsjob.Request) (cupsjob.Result, error) {
	c.calls++
	c.canceled = append(c.canceled, c.jobs...)
	count := uint64(len(c.jobs))
	c.jobs = nil
	if c.afterEffect != nil {
		c.afterEffect()
	}
	return cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.QueueResultType, Profile: r.Profile, Action: r.Action, CommandHash: r.CommandHash, QueueName: r.QueueName, Result: cupsjob.ResultApplied, AffectedJobs: &count}, nil
}

func TestPrinterQueueCommandRequiresDurableStart(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	state := startupManagedState()
	state.DeviceID = identity.DeviceID
	state.PublicIdentityRef = identity.PublicIdentityRef
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	client := Client{StateDir: blocked, Now: func() time.Time { return time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC) }}
	command := testPrinterQueueCommand(cupsjob.ActionCancelAll)
	controller := &durableQueueController{jobs: []string{"original"}}
	err = client.applyPrinterQueueCommand(context.Background(), &state, identity, nil, DesiredSnapshot{SessionID: "session-current", PrinterQueueCommand: &command}, controller)
	if err == nil || controller.calls != 0 || len(controller.jobs) != 1 || state.PrinterQueueCommandSequence != 0 {
		t.Fatalf("undurable command executed: err=%v calls=%d state=%+v", err, controller.calls, state)
	}
}

func TestPrinterQueueCommandInterruptedResultDoesNotRepeatCancelAll(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	state := startupManagedState()
	state.DeviceID = identity.DeviceID
	state.PublicIdentityRef = identity.PublicIdentityRef
	dir := t.TempDir()
	if err := SaveStateAtomic(dir, state); err != nil {
		t.Fatal(err)
	}
	client := Client{StateDir: dir, Now: func() time.Time { return time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC) }}
	command := testPrinterQueueCommand(cupsjob.ActionCancelAll)
	path := StatePath(dir)
	saved := filepath.Join(dir, "saved-state.json")
	controller := &durableQueueController{jobs: []string{"original"}, afterEffect: func() {
		if err := os.Rename(path, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}}
	err = client.applyPrinterQueueCommand(context.Background(), &state, identity, nil, DesiredSnapshot{SessionID: "session-current", PrinterQueueCommand: &command}, controller)
	if err == nil || controller.calls != 1 || len(controller.canceled) != 1 {
		t.Fatalf("expected effect followed by result-save failure: %v calls=%d", err, controller.calls)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, path); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	controller.afterEffect = nil
	controller.jobs = []string{"new-after-interruption"}
	replay, err := applyPrinterQueueCommandPair(t, client, &restarted, identity, command, controller, true)
	if err != nil || controller.calls != 1 || len(controller.jobs) != 1 || replay.Result != cupsjob.ResultFailed || replay.ErrorCategory == nil || *replay.ErrorCategory != cupsjob.ErrorHelper || replay.AffectedJobs == nil || *replay.AffectedJobs != 0 || replay.Sequence != 1 {
		t.Fatalf("interrupted command replayed unsafely: %+v err=%v calls=%d", replay, err, controller.calls)
	}
	if !VerifySignature(identity.PublicIdentityRef, PrinterQueueCommandResultCanonical(replay), replay.Signature) {
		t.Fatal("replay signature invalid")
	}
	command.CommandID = "33333333-3333-4333-8333-333333333333"
	command.PayloadHash = PrinterQueueCommandHash(command)
	next, err := applyPrinterQueueCommandPair(t, client, &restarted, identity, command, controller, true)
	if err != nil || controller.calls != 2 || len(controller.jobs) != 0 || next.Result != cupsjob.ResultApplied || next.Sequence != 2 {
		t.Fatalf("new command did not execute: %+v err=%v calls=%d", next, err, controller.calls)
	}
}

func TestQueueDeletionIsLimitedToLocalUSBKiosks(t *testing.T) {
	command := testPrinterQueueCommand(cupsjob.ActionDelete)
	command.AuthorityKind = "kiosk-usb"
	if !validPrinterQueueAuthorityForKind(command, DeviceKindKiosk) {
		t.Fatal("local USB deletion rejected")
	}
	if validPrinterQueueAuthorityForKind(command, DeviceKindPrintServer) {
		t.Fatal("USB deletion allowed on print bridge")
	}
	command.AuthorityKind = "managed-wireless"
	if validPrinterQueueAuthorityForKind(command, DeviceKindPrintServer) {
		t.Fatal("bridge deletion bypasses reconcile")
	}
}

func TestQueueUSBAdditionIsKioskOnly(t *testing.T) {
	command := testPrinterQueueCommand(cupsjob.ActionAddUSB)
	if !validPrinterQueueAuthorityForKind(command, DeviceKindKiosk) || validPrinterQueueAuthorityForKind(command, DeviceKindPrintServer) {
		t.Fatal("incorrect USB add authority")
	}
	command.AuthorityKind = "managed-wireless"
	if validPrinterQueueAuthorityForKind(command, DeviceKindPrintServer) {
		t.Fatal("USB add allowed on print bridge")
	}
}
