package enrollment

import (
	"context"
	"crypto"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/operations"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type failingIdentitySigner struct {
	crypto.Signer
	calls atomic.Int32
}

func (s *failingIdentitySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	return nil, errors.New("TPM authorization failed")
}
func TestSigningFailureNeverAutomaticallyRetries(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false, true)
	identity := fixture.identity
	state, err := LoadState(client.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	broken := &failingIdentitySigner{Signer: identity.signer}
	identity.signer = broken
	_, err = client.ConnectAndHeartbeatWithRetry(context.Background(), state, identity, SessionOptions{HeartbeatSequence: 1}, 5)
	if !errors.Is(err, ErrIdentity) {
		t.Fatalf("lost fatal identity cause: %v", err)
	}
	if broken.calls.Load() != 1 {
		t.Fatalf("signer retried %d times", broken.calls.Load())
	}
}

func TestSignedEvidencePreservesFatalSignerError(t *testing.T) {
	for _, kind := range []string{"inventory", "operation-ack", "operation-result", "remote-poll"} {
		t.Run(kind, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false, true)
			identity := fixture.identity
			broken := &failingIdentitySigner{Signer: identity.signer}
			identity.signer = broken
			state := fixture.state
			ctx := context.Background()
			command := operations.Command{Version: 1, Type: "operation.command", CommandID: "command", CommandType: operations.CommandReboot, PayloadHash: "hash"}
			var err error
			switch kind {
			case "inventory":
				err = client.sendInventoryIfNeeded(ctx, &state, identity, nil, operations.NewInventoryCollector(), time.Second)
			case "operation-ack":
				err = client.sendOperationAck(ctx, &state, identity, nil, command, false, time.Second)
			case "operation-result":
				err = client.sendOperationResult(ctx, &state, identity, nil, nil, command, operations.OperationResult{Version: operations.OperationVersion, Type: operations.OperationType, CommandType: operations.CommandReboot, Result: operations.ResultScheduled, ObservedAt: client.now().UTC().Format(time.RFC3339Nano)}, time.Second)
			case "remote-poll":
				_, err = client.pollRemoteDesktopAndApply(ctx, &state, identity, &websocket.Conn{}, state.SessionID, 1, &RemoteDesktopManager{})
			}
			if !errors.Is(err, ErrIdentity) || !permanentSessionError(err) || broken.calls.Load() != 1 {
				t.Fatalf("%s discarded fatal signing error or retried: %v (%d)", kind, err, broken.calls.Load())
			}
		})
	}
}
