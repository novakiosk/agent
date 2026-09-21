package enrollment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/novakiosk/agent/cupsjob"
	"github.com/novakiosk/agent/cupsreconcile"
	"github.com/novakiosk/agent/printer"
)

func bridgeReporter() *fakePrinterReporter {
	return &fakePrinterReporter{report: printer.Report{
		Version: printer.Version, Type: printer.Type, Source: printer.Source,
		ObservedAt: "2026-08-24T12:00:00Z", Scheduler: printer.SchedulerRunning,
		Transport: printer.TransportReachable, Queues: []printer.QueueReport{},
	}}
}

type fakePrinterReconciler struct {
	calls  int
	result cupsreconcile.HelperResult
}

func (reconciler *fakePrinterReconciler) Apply(_ context.Context, desired cupsreconcile.Desired) cupsreconcile.HelperResult {
	reconciler.calls++
	result := reconciler.result
	result.DesiredHash = desired.DesiredHash
	return result
}

func TestPrintBridgeRejectsKioskState(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	err := client.PrintBridge(context.Background(), PrintBridgeOptions{PrinterReporter: bridgeReporter()})
	if err == nil || !strings.Contains(err.Error(), "requires print-server state") {
		t.Fatalf("error = %v, want kiosk-state rejection", err)
	}
	if fixture.handshakes.Load() != 0 {
		t.Fatalf("handshakes = %d, want no network connection", fixture.handshakes.Load())
	}
}

func TestPrintBridgeRejectsNonNullKioskState(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.state.DeviceKind = DeviceKindPrintServer
	if err := SaveStateAtomic(fixture.stateDir, fixture.state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := client.PrintBridge(ctx, PrintBridgeOptions{HeartbeatInterval: time.Millisecond, ReconnectDelay: time.Millisecond, PrinterReporter: bridgeReporter()})
	if err == nil || !strings.Contains(err.Error(), "non-null kiosk state") {
		t.Fatalf("error = %v, want non-null snapshot rejection", err)
	}
}

func TestPrintBridgeRejectsKioskExtensions(t *testing.T) {
	for _, kind := range []string{"idle", "browser", "remote-poll"} {
		t.Run(kind, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			fixture.state.DeviceKind, fixture.nullDesired = DeviceKindPrintServer, true
			switch kind {
			case "idle":
				desired := testIdleDesired(t)
				fixture.idle = &desired
			case "browser":
				fixture.browserCommand = browserCommandFixture("reload", nil)
			case "remote-poll":
				fixture.remoteDesktopV2 = true
			}
			if err := SaveStateAtomic(fixture.stateDir, fixture.state); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := client.PrintBridge(ctx, PrintBridgeOptions{PrinterReporter: bridgeReporter()})
			if err == nil || !strings.Contains(err.Error(), "non-null kiosk state") {
				t.Fatalf("%s state was not rejected: %v", kind, err)
			}
		})
	}
}

func TestPrintBridgeRequiresAdvertisedReconciler(t *testing.T) {
	client := Client{PrinterReconcileSupported: true}
	if err := client.PrintBridge(t.Context(), PrintBridgeOptions{PrinterReporter: bridgeReporter()}); err == nil || !strings.Contains(err.Error(), "printer reconciler is required") {
		t.Fatalf("missing reconciler was not rejected before startup: %v", err)
	}
}

func TestPrintBridgeReportsPrintersOnNullSnapshot(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.state.DeviceKind = DeviceKindPrintServer
	fixture.nullDesired = true
	if err := SaveStateAtomic(fixture.stateDir, fixture.state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.PrintBridge(ctx, PrintBridgeOptions{HeartbeatInterval: time.Millisecond, ReconnectDelay: time.Millisecond, PrinterReporter: bridgeReporter()})
	}()
	select {
	case report := <-fixture.printerReports:
		if report.Sequence != 1 || report.DeviceID != fixture.state.DeviceID {
			t.Fatalf("printer report = %+v", report)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for signed printer report")
	}
	deadline := time.NewTimer(3 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		state, err := LoadState(fixture.stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if state.LastPrinterReportAccepted && state.PrinterReportSequence == 1 {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("timed out waiting for printer report acceptance")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("PrintBridge error = %v, want context cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PrintBridge did not stop after cancellation")
	}
	state, err := LoadState(fixture.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !state.LastPrinterReportAccepted || state.PrinterReportSequence != 1 {
		t.Fatalf("printer report state = %+v", state)
	}
}

func TestPrintBridgeAppliesDesiredOnceAndReplaysSignedAck(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	fixture.state.DeviceKind = DeviceKindPrintServer
	fixture.nullDesired = true
	client.PrinterReconcileSupported = true
	desired := cupsreconcile.Desired{Version: 1, Type: cupsreconcile.DesiredType, Queues: []cupsreconcile.Queue{}}
	hash, err := desired.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	desired.DesiredHash = hash
	fixture.printerDesired = &desired
	if err := SaveStateAtomic(fixture.stateDir, fixture.state); err != nil {
		t.Fatal(err)
	}
	reconciler := &fakePrinterReconciler{result: cupsreconcile.HelperResult{Version: 1, Type: "printer.helper.result", Result: cupsreconcile.ResultApplied}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.PrintBridge(ctx, PrintBridgeOptions{HeartbeatInterval: time.Millisecond, ReconnectDelay: time.Millisecond, PrinterReporter: bridgeReporter(), PrinterReconciler: reconciler})
	}()
	for range 2 {
		select {
		case ack := <-fixture.printerAcks:
			if ack.DesiredHash != hash || ack.Result != cupsreconcile.ResultApplied {
				t.Fatalf("ack = %+v", ack)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for printer desired ACK")
		}
	}
	cancel()
	<-done
	if reconciler.calls != 1 {
		t.Fatalf("reconciler calls = %d, want 1", reconciler.calls)
	}
}

func TestPrintBridgeReconcilesBeforeCommandsAndRecoversLostResults(t *testing.T) {
	for _, kind := range []string{"job", "queue"} {
		for _, drop := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/lost=%v", kind, drop), func(t *testing.T) {
				fixture, client, _ := newRunFixture(t, false, false)
				fixture.state.DeviceKind = DeviceKindPrintServer
				fixture.nullDesired = true
				fixture.printerCommandResults = make(chan string, 8)
				fixture.dropPrinterResult = drop
				client.PrinterReconcileSupported = true
				desired := cupsreconcile.Desired{Version: 1, Type: cupsreconcile.DesiredType, Queues: []cupsreconcile.Queue{}}
				desired.DesiredHash, _ = desired.PayloadHash()
				fixture.printerDesired = &desired
				job := testPrinterJobCommand()
				queue := testPrinterQueueCommand(cupsjob.ActionPause)
				job.IssuedAt = client.now().Add(-time.Minute).Format(time.RFC3339Nano)
				job.ExpiresAt = client.now().Add(time.Minute).Format(time.RFC3339Nano)
				job.AuthorityKind = "managed-wireless"
				job.PayloadHash = PrinterJobCommandHash(job)
				queue.IssuedAt = job.IssuedAt
				queue.ExpiresAt = job.ExpiresAt
				queue.AuthorityKind = "managed-wireless"
				queue.PayloadHash = PrinterQueueCommandHash(queue)
				if kind == "job" {
					client.PrinterJobCancelSupported = true
					fixture.printerJobCommand = &job
				} else {
					client.PrinterQueueControlSupported = true
					fixture.printerQueueCommand = &queue
				}
				if err := SaveStateAtomic(fixture.stateDir, fixture.state); err != nil {
					t.Fatal(err)
				}
				reconciler := &fakePrinterReconciler{result: cupsreconcile.HelperResult{Version: 1, Type: "printer.helper.result", Result: cupsreconcile.ResultApplied}}
				canceler := &countingPrinterJobCanceler{result: cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.ResultType, Profile: "print-bridge", Action: job.Action, CommandHash: job.PayloadHash, QueueName: job.QueueName, CUPSJobID: job.CUPSJobID, Result: cupsjob.ResultApplied}}
				controller := &countingPrinterQueueController{result: cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.QueueResultType, Profile: "print-bridge", Action: queue.Action, CommandHash: queue.PayloadHash, QueueName: queue.QueueName, Result: cupsjob.ResultApplied}}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- client.PrintBridge(ctx, PrintBridgeOptions{HeartbeatInterval: 5 * time.Millisecond, ReconnectDelay: time.Millisecond, PrinterReporter: bridgeReporter(), PrinterReconciler: reconciler, PrinterJobCanceler: canceler, PrinterQueueController: controller})
				}()
				results := 1
				if drop {
					results = 2
				}
				for i := 0; i < results; i++ {
					select {
					case result := <-fixture.printerCommandResults:
						if result != cupsjob.ResultApplied {
							t.Fatalf("result = %s", result)
						}
					case <-ctx.Done():
						t.Fatal("missing command result")
					}
				}
				// A subsequent reconciliation ACK proves the accepted command did not
				// desynchronize this connection's next heartbeat.
				for i := 0; i < results+1; i++ {
					select {
					case <-fixture.printerAcks:
					case <-ctx.Done():
						t.Fatal("heartbeat did not continue")
					}
				}
				cancel()
				<-done
				if got := canceler.calls.Load() + controller.calls.Load(); got != 1 {
					t.Fatalf("action calls = %d", got)
				}
				if reconciler.calls != 1 {
					t.Fatalf("reconcile calls = %d", reconciler.calls)
				}
				expected := int32(1)
				if drop {
					expected = 2
				}
				if fixture.handshakes.Load() != expected {
					t.Fatalf("handshakes = %d", fixture.handshakes.Load())
				}
			})
		}
	}
}
