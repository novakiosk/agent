package enrollment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsjob"
)

func testPrinterJobCommand() PrinterJobCommand {
	command := PrinterJobCommand{Version: ProtocolVersion, Type: "printer.job.command", Profile: ProvisionalIdentityProfile, CommandID: "11111111-1111-4111-8111-111111111111", Action: cupsjob.ActionCancel, AuthorityKind: "kiosk-usb", AuthorityID: "printer-1", QueueName: "USB_ZEBRA", CUPSJobID: 7, JobKey: strings.Repeat("a", 64), IssuedAt: "2026-08-31T10:00:00Z", ExpiresAt: "2026-08-31T10:10:00Z"}
	command.PayloadHash = PrinterJobCommandHash(command)
	return command
}

func TestPrinterJobCommandCanonicalAndValidation(t *testing.T) {
	command := testPrinterJobCommand()
	if err := command.Validate(time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(PrinterJobCommandCanonical(command)), "authorityKind=a2lvc2stdXNi") {
		t.Fatal("canonical authority field missing")
	}
	command.QueueName = "../printer"
	command.PayloadHash = PrinterJobCommandHash(command)
	if err := command.Validate(time.Now(), true); err == nil {
		t.Fatal("unsafe queue accepted")
	}
}

func TestPrinterJobResultRequiresExactTerminalErrorShape(t *testing.T) {
	result := PrinterJobCommandResult{Version: ProtocolVersion, Type: "printer.job.command.result", Profile: ProvisionalIdentityProfile, SessionID: "session", DeviceID: "device", CommandID: testPrinterJobCommand().CommandID, Action: cupsjob.ActionCancel, AuthorityKind: "kiosk-usb", AuthorityID: "printer-1", QueueName: "USB_ZEBRA", CUPSJobID: 7, JobKey: strings.Repeat("a", 64), PayloadHash: testPrinterJobCommand().PayloadHash, Result: cupsjob.ResultApplied, ObservedAt: "2026-08-31T10:01:00.123456789Z", Sequence: 1, Signature: "signature"}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	category := cupsjob.ErrorNotActive
	result.ErrorCategory = &category
	if err := result.Validate(); err == nil {
		t.Fatal("applied result accepted an error")
	}
}

type countingPrinterJobCanceler struct {
	calls  atomic.Int32
	result cupsjob.Result
}

func (canceler *countingPrinterJobCanceler) Cancel(context.Context, cupsjob.Request) (cupsjob.Result, error) {
	canceler.calls.Add(1)
	return canceler.result, nil
}

// applyPrinterJobCommandPair creates the smallest real websocket peer needed
// to exercise the result-before-send/replay protocol. The first peer may
// intentionally close after reading the result to model response loss.
func applyPrinterJobCommandPair(t *testing.T, client Client, state *State, identity Identity, command PrinterJobCommand, canceler PrinterJobCanceler, acknowledge bool) (PrinterJobCommandResult, error) {
	t.Helper()
	received := make(chan PrinterJobCommandResult, 1)
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
		var result PrinterJobCommandResult
		if decodeErr := decodeStrict(data, &result); decodeErr != nil {
			return
		}
		received <- result
		if acknowledge {
			_ = writeSessionMessage(connection, PrinterJobCommandAccepted{Version: ProtocolVersion, Type: "printer.job.command.result.accepted", SessionID: result.SessionID, DeviceID: result.DeviceID, CommandID: result.CommandID, PayloadHash: result.PayloadHash, Sequence: result.Sequence, Disposition: "accepted"}, time.Second)
		}
	}))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		return PrinterJobCommandResult{}, err
	}
	defer connection.Close()
	snapshot := DesiredSnapshot{SessionID: "session-current", DeviceID: state.DeviceID, PrinterJobCommand: &command}
	applyErr := client.applyPrinterJobCommand(context.Background(), state, identity, connection, snapshot, canceler)
	select {
	case result := <-received:
		return result, applyErr
	case <-time.After(2 * time.Second):
		return PrinterJobCommandResult{}, applyErr
	}
}

func TestPrinterJobCommandReplaysPendingResultAfterResponseLossAndExpiry(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	state := State{Version: ProtocolVersion, Status: "Managed", InstanceURL: "https://control.example", EnrollmentID: "enrollment-1", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1", SessionID: "session-old", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-31T09:00:00Z", DeviceKind: DeviceKindKiosk}
	if err := SaveStateAtomic(stateDir, state); err != nil {
		t.Fatal(err)
	}
	command := testPrinterJobCommand()
	canceler := &countingPrinterJobCanceler{result: cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.ResultType, Profile: "kiosk", Action: cupsjob.ActionCancel, CommandHash: command.PayloadHash, QueueName: command.QueueName, CUPSJobID: command.CUPSJobID, Result: cupsjob.ResultApplied}}
	firstClient := Client{StateDir: stateDir, Now: func() time.Time { return time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC) }}
	first, firstErr := applyPrinterJobCommandPair(t, firstClient, &state, identity, command, canceler, false)
	if firstErr == nil {
		t.Fatal("response-loss apply unexpectedly succeeded")
	}
	if canceler.calls.Load() != 1 {
		t.Fatalf("cancel calls after first apply = %d, want 1", canceler.calls.Load())
	}
	persisted, err := LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.LastPrinterJobCommandAccepted || persisted.LastPrinterJobCommandResult != cupsjob.ResultApplied || persisted.PrinterJobCommandSequence != 1 {
		t.Fatalf("pending persisted evidence = %+v", persisted)
	}
	secondClient := Client{StateDir: stateDir, Now: func() time.Time { return time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC) }}
	second, secondErr := applyPrinterJobCommandPair(t, secondClient, &persisted, identity, command, canceler, true)
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	if canceler.calls.Load() != 1 {
		t.Fatalf("cancel calls after expired replay = %d, want no second invocation", canceler.calls.Load())
	}
	if second.ObservedAt != first.ObservedAt || second.Result != first.Result || second.Sequence != first.Sequence || second.PayloadHash != first.PayloadHash {
		t.Fatalf("replayed result = %+v, first = %+v", second, first)
	}
	if second.SessionID != "session-current" {
		t.Fatalf("replayed result session = %q, want current session", second.SessionID)
	}
	finalState, err := LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !finalState.LastPrinterJobCommandAccepted {
		t.Fatal("replayed result was not durably acknowledged")
	}
}

func TestPrinterJobCommandRejectsNewExpiredCommand(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	state := State{Version: ProtocolVersion, Status: "Managed", InstanceURL: "https://control.example", EnrollmentID: "enrollment-1", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1", SessionID: "session-1", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-31T09:00:00Z", DeviceKind: DeviceKindKiosk}
	if err := SaveStateAtomic(stateDir, state); err != nil {
		t.Fatal(err)
	}
	command := testPrinterJobCommand()
	client := Client{StateDir: stateDir, Now: func() time.Time { return time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC) }}
	if err := client.applyPrinterJobCommand(context.Background(), &state, identity, nil, DesiredSnapshot{SessionID: "session-1", DeviceID: state.DeviceID, PrinterJobCommand: &command}, nil); err == nil {
		t.Fatal("new expired command was accepted")
	}
}
