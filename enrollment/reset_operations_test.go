package enrollment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/novakiosk/agent/operations"
)

type resetOperationExecutor struct{ calls atomic.Int32 }

func (executor *resetOperationExecutor) Execute(context.Context, operations.CommandType) operations.OperationResult {
	executor.calls.Add(1)
	return operations.OperationResult{}
}

func TestResetDiscardsOperationJournalBeforeNewEnrollment(t *testing.T) {
	for _, phase := range []operations.JournalPhase{operations.PhaseAccepted, operations.PhaseExecutionStarted, operations.PhaseExecuted, operations.PhaseResultAccepted} {
		t.Run(string(phase), func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			command := operations.Command{Version: operations.CommandVersion, Type: operations.CommandMessageType, CommandID: "11111111-1111-4111-8111-111111111111", CommandType: operations.CommandReboot, IssuedAt: client.now().Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: client.now().Add(time.Minute).Format(time.RFC3339Nano)}
			command.PayloadHash, _ = command.CanonicalPayloadHash()
			journal := map[string]any{"version": operations.OperationJournalVersion, "type": operations.OperationJournalType, "phase": phase, "command": command}
			if phase == operations.PhaseExecuted || phase == operations.PhaseResultAccepted {
				journal["result"] = operations.OperationResult{Version: operations.OperationVersion, Type: operations.OperationType, CommandType: command.CommandType, Result: operations.ResultScheduled, ObservedAt: client.now().Format(time.RFC3339Nano), BootIDBefore: "00112233-4455-6677-8899-aabbccddeeff"}
			}
			data, err := json.Marshal(journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(operations.OperationJournalPath(client.StateDir), data, 0600); err != nil {
				t.Fatal(err)
			}
			identityBefore, _ := os.ReadFile(IdentityPath(client.StateDir))
			profile := filepath.Join(client.StateDir, "browser")
			if err := os.Mkdir(profile, 0700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(profile, "Preferences")
			if err := os.WriteFile(sentinel, []byte("preserved"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Reset(client.StateDir); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(operations.OperationJournalPath(client.StateDir)); !os.IsNotExist(err) {
				t.Fatalf("journal survived reset: %v", err)
			}
			identityAfter, _ := os.ReadFile(IdentityPath(client.StateDir))
			if string(identityBefore) != string(identityAfter) {
				t.Fatal("identity changed")
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "preserved" {
				t.Fatal("browser profile changed")
			}
			fixture.state.EnrollmentID = "new-enrollment"
			fixture.state.IdentityBindingID = "new-binding"
			if err := SaveStateAtomic(client.StateDir, fixture.state); err != nil {
				t.Fatal(err)
			}
			executor := &resetOperationExecutor{}
			coordinator, err := operations.NewCoordinator(operations.CoordinatorConfig{StateDir: client.StateDir, Executor: executor, Clock: client.now})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, present, err := coordinator.CurrentCommand(); err != nil || present {
				t.Fatalf("old command loaded: present=%v err=%v", present, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- client.Run(ctx, RunOptions{OperationExecutor: executor, HeartbeatInterval: 10 * time.Millisecond, BrowserFactory: func(context.Context, string) (Browser, error) { return NewFakeBrowser(nil), nil }})
			}()
			select {
			case ack := <-fixture.acks:
				if ack.Result != "applied" {
					t.Fatalf("new enrollment ACK: %+v", ack)
				}
			case <-ctx.Done():
				t.Fatal("new enrollment blocked by old journal")
			}
			cancel()
			<-done
			if executor.calls.Load() != 0 {
				t.Fatal("old command executed under new enrollment")
			}
			if fixture.handshakes.Load() != 1 {
				t.Fatal("new session disconnected by stale operation result")
			}
		})
	}
}
