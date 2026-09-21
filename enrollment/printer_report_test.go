package enrollment

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/novakiosk/agent/printer"
)

func testPrinterReport(t *testing.T, identity Identity) PrinterReport {
	t.Helper()
	report := printer.Report{
		Version: printer.Version, Type: printer.Type, Source: printer.Source,
		ObservedAt: "2026-08-24T12:34:56Z", Scheduler: printer.SchedulerStopped,
		Transport: printer.TransportReachable, Queues: []printer.QueueReport{},
	}
	hash, err := printer.CanonicalPayloadHash(report)
	if err != nil {
		t.Fatal(err)
	}
	envelope := PrinterReport{Version: ProtocolVersion, Type: PrinterReportType, Profile: ProvisionalIdentityProfile, SessionID: "session-1", DeviceID: identity.DeviceID, Report: report, ReportHash: hash, Sequence: 1}
	signature, err := SignPrinterReport(identity, envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = signature
	return envelope
}

func TestPrinterReportCanonicalSigningAndHashBinding(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope := testPrinterReport(t, identity)
	if err := ValidatePrinterReport(envelope, envelope.SessionID, identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(identity.PublicIdentityRef, PrinterReportCanonical(envelope), envelope.Signature) {
		t.Fatal("valid printer report signature rejected")
	}
	if !strings.Contains(string(PrinterReportCanonical(envelope)), "type=cHJpbnRlci5yZXBvcnQ") {
		t.Fatal("printer report canonical domain is missing")
	}
	changed := envelope
	changed.Sequence++
	if VerifySignature(identity.PublicIdentityRef, PrinterReportCanonical(changed), envelope.Signature) {
		t.Fatal("sequence change retained signature")
	}
	changed = envelope
	changed.ReportHash = strings.Repeat("0", 64)
	if ValidatePrinterReport(changed, changed.SessionID, changed.DeviceID) == nil {
		t.Fatal("mismatched report hash accepted")
	}
}

func TestPrinterReportAcceptedBinding(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope := testPrinterReport(t, identity)
	accepted := PrinterReportAccepted{Version: ProtocolVersion, Type: "printer.report.accepted", SessionID: envelope.SessionID, DeviceID: envelope.DeviceID, ReportHash: envelope.ReportHash, Sequence: envelope.Sequence, Disposition: "accepted"}
	if err := ValidatePrinterReportAccepted(accepted, envelope); err != nil {
		t.Fatal(err)
	}
	accepted.Disposition = "older"
	if err := ValidatePrinterReportAccepted(accepted, envelope); err == nil {
		t.Fatal("older disposition accepted")
	}
}

func TestPrinterReportCadenceAndResponseLossMarker(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	state := State{LastPrinterReportAccepted: true, LastPrinterReportAttemptAt: now.Add(-29 * time.Second).Format(time.RFC3339Nano)}
	if printerReportDue(state, now) {
		t.Fatal("accepted report was due before 30 seconds")
	}
	state.LastPrinterReportAttemptAt = now.Add(-PrinterReportMinInterval).Format(time.RFC3339Nano)
	if !printerReportDue(state, now) {
		t.Fatal("accepted report was not due at 30 seconds")
	}
	state.LastPrinterReportAttemptAt = now.Format(time.RFC3339Nano)
	state.LastPrinterReportAccepted = false
	if !printerReportDue(state, now) {
		t.Fatal("unaccepted response-loss marker did not force retry")
	}
}

type fakePrinterReporter struct {
	report printer.Report
}

func (f *fakePrinterReporter) Collect(context.Context) (printer.Report, error) { return f.report, nil }
