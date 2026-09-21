package enrollment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsreconcile"
)

func sessionTestConnection(t *testing.T, handle func(*websocket.Conn)) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		handle(c)
	}))
	t.Cleanup(server.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestIdleAcknowledgesChangedIdentityWithSamePayload(t *testing.T) {
	for _, change := range []string{"revision", "screen", "unchanged"} {
		t.Run(change, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			desired := testIdleDesired(t)
			state := fixture.state
			state.LastIdleScreenID, state.LastIdleRevisionID, state.LastIdlePayloadHash = desired.IdleScreenID, desired.RevisionID, desired.PayloadHash
			state.LastIdleAckResult, state.LastIdleAckAccepted = "applied", true
			switch change {
			case "revision":
				desired.RevisionID = "revision-2"
				desired.Revision = 2
			case "screen":
				desired.IdleScreenID = "idle-2"
			}
			if IdleScreenPayloadHash(desired) != state.LastIdlePayloadHash {
				t.Fatal("test must retain payload hash")
			}
			received := make(chan IdleAck, 1)
			connection := sessionTestConnection(t, func(c *websocket.Conn) {
				var ack IdleAck
				if c.ReadJSON(&ack) != nil {
					return
				}
				received <- ack
				_ = c.WriteJSON(map[string]any{"version": ProtocolVersion, "type": "idle.desired.ack.accepted", "sessionId": ack.SessionID, "deviceId": ack.DeviceID, "idleScreenId": ack.IdleScreenID, "revisionId": ack.RevisionID, "payloadHash": ack.PayloadHash, "result": ack.Result, "sequence": ack.Sequence, "disposition": "accepted"})
			})
			if err := client.applyIdleAndAcknowledge(context.Background(), &state, fixture.identity, connection, DesiredSnapshot{SessionID: "session-current", Idle: &desired}, &recordingIdleRuntime{}); err != nil {
				t.Fatal(err)
			}
			if change == "unchanged" {
				if state.IdleAckSequence != 0 {
					t.Fatal("unchanged identity was acknowledged again")
				}
				return
			}
			select {
			case ack := <-received:
				if ack.IdleScreenID != desired.IdleScreenID || ack.RevisionID != desired.RevisionID || ack.Sequence != 1 || !state.LastIdleAckAccepted || !VerifySignature(fixture.identity.PublicIdentityRef, IdleAckCanonical(ack), ack.Signature) {
					t.Fatalf("incorrect acknowledgement: %+v", ack)
				}
			default:
				t.Fatal("changed idle identity was not acknowledged")
			}
		})
	}
}

func TestPrinterDesiredUsesProtocolMessageBound(t *testing.T) {
	for _, tc := range []struct {
		version  int
		oversize bool
	}{{1, false}, {1, true}, {2, false}, {2, true}} {
		oversize := tc.oversize
		t.Run(fmt.Sprintf("v%d/oversize=%v", tc.version, oversize), func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			state := fixture.state
			desired := cupsreconcile.Desired{Version: 1, Type: cupsreconcile.DesiredType, SessionID: "session-current", DeviceID: state.DeviceID}
			for i := range 20 {
				q := cupsreconcile.Queue{PrinterID: fmt.Sprint(i), LocalName: fmt.Sprintf("q%d", i), Mode: cupsreconcile.ModeExisting}
				for j := range 20 {
					q.Options = append(q.Options, cupsreconcile.Option{Name: fmt.Sprintf("Option%d", j), Value: "ChoiceValue"})
				}
				desired.Queues = append(desired.Queues, q)
			}
			desired.DesiredHash, _ = desired.PayloadHash()
			data, _ := json.Marshal(desired)
			if len(data) <= MaxCanonicalBytes || len(data) >= cupsreconcile.MaxMessageBytes {
				t.Fatalf("fixture size %d", len(data))
			}
			if _, err := cupsreconcile.DecodeDesired(data, desired.SessionID, state.DeviceID); err != nil {
				t.Fatal(err)
			}
			if tc.version == 2 {
				direct := cupsreconcile.DesiredV2{Version: 2, Type: desired.Type, SessionID: desired.SessionID, DeviceID: desired.DeviceID, Queues: desired.Queues}
				for i := range direct.Queues {
					q := &direct.Queues[i]
					q.LocalName = fmt.Sprintf("NOVA_QUEUE_%d", i)
					q.Mode = cupsreconcile.ModeDirect
					q.DisplayName = "Test printer"
					q.Location = "Test room"
					q.PrivateIP = "192.168.1.2"
					q.ConnectionProfile = cupsreconcile.ConnectionZebraAppSocket
					q.DriverProfile = cupsreconcile.DriverZebraZPL
				}
				direct.DesiredHash, _ = direct.PayloadHash()
				data, _ = json.Marshal(direct)
				if _, err := cupsreconcile.DecodeDesiredV2(data, direct.SessionID, direct.DeviceID); err != nil {
					t.Fatal(err)
				}
				if len(data) <= MaxCanonicalBytes || len(data) >= cupsreconcile.MaxMessageBytes {
					t.Fatalf("direct fixture size %d", len(data))
				}
			}
			if oversize {
				data = append(data, []byte(strings.Repeat(" ", cupsreconcile.MaxMessageBytes-len(data)+1))...)
			}
			connection := sessionTestConnection(t, func(c *websocket.Conn) {
				if c.WriteMessage(websocket.TextMessage, data) != nil {
					return
				}
				var ack cupsreconcile.Ack
				if c.ReadJSON(&ack) != nil {
					return
				}
				_ = c.WriteJSON(printerDesiredAckAccepted{Version: ack.Version, Type: "printer.desired.ack.accepted", SessionID: ack.SessionID, DeviceID: ack.DeviceID, DesiredHash: ack.DesiredHash, Result: ack.Result, Sequence: ack.Sequence, Disposition: "accepted"})
			})
			applier := &sizedPrinterReconciler{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := client.receiveApplyAndAcknowledgePrinterDesired(ctx, &state, fixture.identity, connection, desired.SessionID, applier)
			if oversize {
				if err == nil || applier.calls != 0 {
					t.Fatalf("oversize desired applied: %v calls=%d", err, applier.calls)
				}
				return
			}
			if err != nil || applier.calls != 1 || !state.LastPrinterReconcileAccepted {
				t.Fatalf("valid desired rejected: %v calls=%d", err, applier.calls)
			}
		})
	}
}

type sizedPrinterReconciler struct{ calls int }

func (r *sizedPrinterReconciler) Apply(_ context.Context, d cupsreconcile.Desired) cupsreconcile.HelperResult {
	r.calls++
	return cupsreconcile.HelperResult{Version: d.Version, DesiredHash: d.DesiredHash, Result: cupsreconcile.ResultApplied}
}
func (r *sizedPrinterReconciler) ApplyV2(_ context.Context, d cupsreconcile.DesiredV2) cupsreconcile.HelperResult {
	r.calls++
	return cupsreconcile.HelperResult{Version: d.Version, DesiredHash: d.DesiredHash, Result: cupsreconcile.ResultApplied}
}

type retryIdleRemovalRuntime struct {
	calls     int
	failFirst bool
}

func (runtime *retryIdleRemovalRuntime) Apply(context.Context, *IdleDesired) error {
	runtime.calls++
	if runtime.failFirst && runtime.calls == 1 {
		return fmt.Errorf("transient idle cleanup failure")
	}
	return nil
}
func (*retryIdleRemovalRuntime) Close() error { return nil }

func TestIdleRemovalRetriesFailedAcceptedAndStaleState(t *testing.T) {
	for _, kind := range []string{"accepted", "duplicate", "poisoned", "stale"} {
		t.Run(kind, func(t *testing.T) {
			identity, err := GenerateIdentity()
			if err != nil {
				t.Fatal(err)
			}
			desired := testIdleDesired(t)
			state := State{Version: ProtocolVersion, Status: "Managed", InstanceURL: "https://example.test", EnrollmentID: "enrollment-1", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "binding-1", SessionID: "session-1", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-24T12:00:00Z", LastIdleScreenID: desired.IdleScreenID, LastIdleRevisionID: desired.RevisionID, LastIdlePayloadHash: desired.PayloadHash, LastIdleAckResult: "applied", LastIdleAckAccepted: true}
			client := Client{StateDir: t.TempDir()}
			connection := sessionTestConnection(t, func(c *websocket.Conn) {
				for index := 0; ; index++ {
					var ack IdleAck
					if err := c.ReadJSON(&ack); err != nil {
						return
					}
					if !VerifySignature(identity.PublicIdentityRef, IdleAckCanonical(ack), ack.Signature) {
						return
					}
					disposition := "accepted"
					if index == 0 && (kind == "duplicate" || kind == "stale") {
						disposition = kind
					}
					if err := c.WriteJSON(map[string]any{"version": ProtocolVersion, "type": "idle.desired.ack.accepted", "sessionId": ack.SessionID, "deviceId": ack.DeviceID, "idleScreenId": ack.IdleScreenID, "revisionId": ack.RevisionID, "payloadHash": ack.PayloadHash, "result": ack.Result, "sequence": ack.Sequence, "disposition": disposition}); err != nil {
						return
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			runtime := &retryIdleRemovalRuntime{failFirst: kind != "stale"}
			snapshot := DesiredSnapshot{SessionID: "session-1"}
			if err := client.applyIdleAndAcknowledge(ctx, &state, identity, connection, snapshot, runtime); err != nil {
				t.Fatal(err)
			}
			if state.LastIdleRemoved {
				t.Error("unsuccessful or stale removal marked complete")
			}
			if kind == "poisoned" {
				state.LastIdleRemoved = true // State written by the previous buggy implementation.
				if err := SaveStateAtomic(client.StateDir, state); err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := LoadState(client.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.applyIdleAndAcknowledge(ctx, &loaded, identity, connection, snapshot, runtime); err != nil {
				t.Fatal(err)
			}
			if runtime.calls != 2 || loaded.LastIdleAckResult != "applied" || !loaded.LastIdleRemoved || !loaded.LastIdleAckAccepted {
				t.Fatalf("removal did not recover: calls=%d result=%s removed=%v", runtime.calls, loaded.LastIdleAckResult, loaded.LastIdleRemoved)
			}
			loaded, err = LoadState(client.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.applyIdleAndAcknowledge(ctx, &loaded, identity, connection, snapshot, runtime); err != nil || runtime.calls != 2 {
				t.Fatalf("successful removal was not deduplicated: %v calls=%d", err, runtime.calls)
			}
		})
	}
}

type defaultAwareReconciler struct {
	applies, defaults int
	failDefault       bool
}

func (r *defaultAwareReconciler) Apply(_ context.Context, d cupsreconcile.Desired) cupsreconcile.HelperResult {
	r.applies++
	return cupsreconcile.HelperResult{Version: 1, DesiredHash: d.DesiredHash, Result: cupsreconcile.ResultApplied}
}
func (r *defaultAwareReconciler) MaintainDefault(context.Context, cupsreconcile.Desired) error {
	r.defaults++
	if r.failDefault {
		return fmt.Errorf("CUPS default unavailable")
	}
	return nil
}
func TestDefaultMaintenanceReassertsWithoutRecreatingQueues(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	state := fixture.state
	selected := "USB_A"
	desired := cupsreconcile.Desired{Version: 1, Type: cupsreconcile.DesiredType, SessionID: "session-current", DeviceID: state.DeviceID, DefaultQueue: &selected, Queues: []cupsreconcile.Queue{{PrinterID: "a", LocalName: "USB_A", Mode: cupsreconcile.ModeExisting}, {PrinterID: "b", LocalName: "USB_B", Mode: cupsreconcile.ModeExisting}}}
	applier := &defaultAwareReconciler{}
	for i := 0; i < 4; i++ {
		if i == 1 {
			selected = "USB_B"
		}
		applier.failDefault = i == 2
		desired.DesiredHash, _ = desired.PayloadHash()
		connection := sessionTestConnection(t, func(c *websocket.Conn) {
			if c.WriteJSON(desired) != nil {
				return
			}
			var ack cupsreconcile.Ack
			if c.ReadJSON(&ack) != nil {
				return
			}
			_ = c.WriteJSON(printerDesiredAckAccepted{Version: 1, Type: "printer.desired.ack.accepted", SessionID: ack.SessionID, DeviceID: ack.DeviceID, DesiredHash: ack.DesiredHash, Result: ack.Result, Sequence: ack.Sequence, Disposition: "accepted"})
		})
		if err := client.receiveApplyAndAcknowledgePrinterDesired(context.Background(), &state, fixture.identity, connection, desired.SessionID, applier); err != nil {
			t.Fatal(err)
		}
		var err error
		state, err = LoadState(client.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		if state.PrinterQueuesApplyPending == nil || *state.PrinterQueuesApplyPending {
			t.Fatal("queue success did not survive default maintenance and reload")
		}
		if (state.LastPrinterReconcileResult == cupsreconcile.ResultFailed) != applier.failDefault {
			t.Fatal("untruthful default result")
		}
	}
	if applier.applies != 1 || applier.defaults != 4 {
		t.Fatalf("queue/default calls: %d/%d", applier.applies, applier.defaults)
	}
}
