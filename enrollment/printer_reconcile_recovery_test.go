package enrollment

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsreconcile"
)

type recoveryPrinterApplier struct {
	calls       int
	actual      string
	fail        bool
	beforeApply func()
}

func (r *recoveryPrinterApplier) Apply(_ context.Context, d cupsreconcile.Desired) cupsreconcile.HelperResult {
	if r.beforeApply != nil {
		r.beforeApply()
	}
	r.calls++
	r.actual = d.Queues[0].Options[0].Value
	result := cupsreconcile.HelperResult{Version: 1, DesiredHash: d.DesiredHash, Result: cupsreconcile.ResultApplied}
	if r.fail {
		result.Result, result.ErrorCategory = cupsreconcile.ResultFailed, cupsreconcile.ErrorApply
	}
	return result
}
func reconcileRecoveryDesired(t *testing.T, state State, resolution string) cupsreconcile.Desired {
	t.Helper()
	d := cupsreconcile.Desired{Version: 1, Type: cupsreconcile.DesiredType, SessionID: "session-current", DeviceID: state.DeviceID, Queues: []cupsreconcile.Queue{{PrinterID: "usb-a", LocalName: "USB_A", Mode: cupsreconcile.ModeExisting, Options: []cupsreconcile.Option{{Name: "Resolution", Value: resolution}}}}}
	var err error
	d.DesiredHash, err = d.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func reconcileRecovery(t *testing.T, client Client, state *State, identity Identity, d cupsreconcile.Desired, applier cupsreconcile.Applier) error {
	t.Helper()
	c := sessionTestConnection(t, func(c *websocket.Conn) {
		if c.WriteJSON(d) != nil {
			return
		}
		var ack cupsreconcile.Ack
		if c.ReadJSON(&ack) != nil {
			return
		}
		_ = c.WriteJSON(printerDesiredAckAccepted{Version: 1, Type: "printer.desired.ack.accepted", SessionID: ack.SessionID, DeviceID: ack.DeviceID, DesiredHash: ack.DesiredHash, Result: ack.Result, Sequence: ack.Sequence, Disposition: "accepted"})
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	return client.receiveApplyAndAcknowledgePrinterDesired(ctx, state, identity, c, d.SessionID, applier)
}
func TestPrinterQueuesReapplyAfterPartialFailure(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	state := fixture.state
	applier := &recoveryPrinterApplier{}
	for i, resolution := range []string{"203dpi", "300dpi", "203dpi"} {
		applier.fail = i == 1
		if err := reconcileRecovery(t, client, &state, fixture.identity, reconcileRecoveryDesired(t, state, resolution), applier); err != nil {
			t.Fatal(err)
		}
		var err error
		state, err = LoadState(client.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && (state.PrinterQueuesApplyPending == nil || !*state.PrinterQueuesApplyPending || state.PrinterQueuesAppliedHash != "") {
			t.Fatal("failed apply retained success evidence")
		}
	}
	if applier.calls != 3 || applier.actual != "203dpi" || state.LastPrinterReconcileResult != cupsreconcile.ResultApplied {
		t.Fatalf("partial change not repaired: %+v %+v", applier, state)
	}
}
func TestPrinterQueuesRecoverInterruptedApplyBeforeAck(t *testing.T) {
	for _, prior := range []string{"first-apply", "cached-success", "legacy-success"} {
		t.Run(prior, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			state := fixture.state
			a := reconcileRecoveryDesired(t, state, "203dpi")
			applier := &recoveryPrinterApplier{}
			if prior != "first-apply" {
				if err := reconcileRecovery(t, client, &state, fixture.identity, a, applier); err != nil {
					t.Fatal(err)
				}
				if prior == "legacy-success" {
					state.PrinterQueuesAppliedHash = ""
					state.PrinterQueuesApplyPending = nil
				}
				if err := SaveStateAtomic(client.StateDir, state); err != nil {
					t.Fatal(err)
				}
			}
			previousHash, previousSequence := state.PrinterDesiredHash, state.PrinterAckSequence
			interrupted := false
			applier.beforeApply = func() {
				persisted, err := LoadState(client.StateDir)
				if err != nil {
					t.Fatal(err)
				}
				if persisted.PrinterQueuesApplyPending == nil || !*persisted.PrinterQueuesApplyPending || persisted.PrinterQueuesAppliedHash != "" {
					t.Fatal("invalidation was not durable before helper")
				}
				if persisted.PrinterDesiredHash != previousHash || persisted.PrinterAckSequence != previousSequence {
					t.Fatal("invalidation changed prior ACK evidence")
				}
				applier.actual = "300dpi" // CUPS changed before the process was interrupted.
				interrupted = true
				panic("simulated process interruption")
			}
			func() {
				defer func() {
					if value := recover(); value != "simulated process interruption" {
						t.Fatalf("unexpected interruption: %v", value)
					}
				}()
				_ = reconcileRecovery(t, client, &state, fixture.identity, reconcileRecoveryDesired(t, state, "300dpi"), applier)
			}()
			if !interrupted {
				t.Fatal("Apply did not run")
			}
			var err error
			state, err = LoadState(client.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			applier.beforeApply = nil
			before := applier.calls
			if err := reconcileRecovery(t, client, &state, fixture.identity, a, applier); err != nil {
				t.Fatal(err)
			}
			if applier.calls != before+1 || applier.actual != "203dpi" {
				t.Fatal("interrupted apply was deduplicated")
			}
		})
	}
}
func TestPrinterQueuesLegacyFailedCacheReappliesOnce(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	state := fixture.state
	a := reconcileRecoveryDesired(t, state, "203dpi")
	applier := &recoveryPrinterApplier{}
	if err := reconcileRecovery(t, client, &state, fixture.identity, a, applier); err != nil {
		t.Fatal(err)
	}
	state.PrinterQueuesApplyPending = nil
	state.LastPrinterReconcileResult, state.LastPrinterReconcileError = cupsreconcile.ResultFailed, cupsreconcile.ErrorApply
	applier.actual = "300dpi"
	if err := SaveStateAtomic(client.StateDir, state); err != nil {
		t.Fatal(err)
	}
	var err error
	state, err = LoadState(client.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := reconcileRecovery(t, client, &state, fixture.identity, a, applier); err != nil {
			t.Fatal(err)
		}
	}
	if applier.calls != 2 || applier.actual != "203dpi" {
		t.Fatalf("legacy recovery calls=%d actual=%s", applier.calls, applier.actual)
	}
}
func TestPrinterQueuesFailedInvalidationBlocksApply(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	state := fixture.state
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	client.StateDir = blocker
	applier := &recoveryPrinterApplier{}
	if err := reconcileRecovery(t, client, &state, fixture.identity, reconcileRecoveryDesired(t, state, "203dpi"), applier); err == nil || applier.calls != 0 {
		t.Fatalf("invalidation failure: %v, helper calls=%d", err, applier.calls)
	}
}
