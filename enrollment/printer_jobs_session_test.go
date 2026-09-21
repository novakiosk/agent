package enrollment

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/printer"
)

type sessionJobsReporter struct{ report printer.Jobs }

func (r sessionJobsReporter) Collect(context.Context) (printer.Jobs, error) { return r.report, nil }

func TestPrinterJobsSessionReporting(t *testing.T) {
	for _, role := range []string{"kiosk", "bridge"} {
		for _, response := range []string{"accepted", "lost", "mismatched"} {
			t.Run(role+"/"+response, func(t *testing.T) {
				fixture, client, _ := newRunFixture(t, false, false)
				fixture.nullDesired = true
				if role == "bridge" {
					fixture.state.DeviceKind = DeviceKindPrintServer
				}
				if err := SaveStateAtomic(fixture.stateDir, fixture.state); err != nil {
					t.Fatal(err)
				}
				client.PrinterJobsSupported = true
				fixture.printerJobsProgress = make(chan State, 32)
				reports := make(chan PrinterJobsReport, 4)
				reporter := sessionJobsReporter{printer.Jobs{Version: printer.JobsVersion, Type: printer.JobsType, Source: printer.JobsSource, ObservedAt: "2026-08-24T12:00:00Z", Jobs: []printer.ActiveJob{{QueueName: "USB_A", JobKey: printer.JobsJobKey("USB_A", 42, 1024, "2026-08-24T11:59:00Z"), CUPSJobID: 42, SizeBytes: 1024, SubmittedAt: "2026-08-24T11:59:00Z"}}}}
				if err := reporter.report.Validate(); err != nil {
					t.Fatal(err)
				}
				fixture.printerJobsHandler = func(c *websocket.Conn, report PrinterJobsReport) bool {
					state, err := LoadState(fixture.stateDir)
					if err != nil || state.PrinterJobsSequence != report.Sequence || state.LastPrinterJobsHash != report.ReportHash || state.LastPrinterJobsAccepted || state.LastPrinterJobsAttemptAt == "" {
						t.Errorf("report must be durably pending before transmission: %+v, %v", state, err)
						return false
					}
					reports <- report
					if report.Sequence == 1 && response == "lost" {
						return false
					}
					ack := PrinterJobsAccepted{Version: ProtocolVersion, Type: PrinterJobsType + ".accepted", SessionID: report.SessionID, DeviceID: report.DeviceID, ReportHash: report.ReportHash, Sequence: report.Sequence, Disposition: "accepted"}
					if response == "mismatched" {
						ack.ReportHash = "wrong-hash"
					}
					return c.WriteJSON(ack) == nil
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				done := make(chan error, 1)
				go func() {
					if role == "bridge" {
						done <- client.PrintBridge(ctx, PrintBridgeOptions{HeartbeatInterval: 100 * time.Millisecond, ReconnectDelay: time.Millisecond, PrinterReporter: bridgeReporter(), PrinterJobsReporter: reporter})
					} else {
						done <- client.Run(ctx, RunOptions{HeartbeatInterval: 100 * time.Millisecond, ReconnectDelay: time.Millisecond, PrinterJobsReporter: reporter, BrowserFactory: func(context.Context, string) (Browser, error) { return NewFakeBrowser(nil), nil }})
					}
				}()
				defer func() {
					cancel()
					if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("session exit: %v", err)
					}
				}()
				count := 1
				if response != "accepted" {
					count = 2
				}
				var last PrinterJobsReport
				for i := 1; i <= count; i++ {
					select {
					case last = <-reports:
						if last.Sequence != uint64(i) || !reflect.DeepEqual(last.Report, reporter.report) {
							t.Fatalf("report %d: %+v", i, last)
						}
						if last.SessionID != "session-1" && i == 1 {
							t.Fatalf("first session: %s", last.SessionID)
						}
						if i == 2 && last.SessionID != "session-2" {
							t.Fatalf("retry did not reconnect: %s", last.SessionID)
						}
					case <-ctx.Done():
						t.Fatal("missing active-job report")
					}
				}
				if response == "mismatched" {
					cancel()
					state, err := LoadState(fixture.stateDir)
					if err != nil || state.LastPrinterJobsAccepted {
						t.Fatalf("mismatched ACK accepted: %+v %v", state, err)
					}
					return
				}
				for {
					select {
					case state := <-fixture.printerJobsProgress:
						if !state.LastPrinterJobsAccepted {
							continue
						}
						if state.PrinterJobsSequence != last.Sequence || state.LastPrinterJobsHash != last.ReportHash {
							t.Fatalf("accepted state: %+v", state)
						}
						return
					case <-ctx.Done():
						t.Fatal("accepted printer jobs not persisted")
					}
				}
			})
		}
	}
}
