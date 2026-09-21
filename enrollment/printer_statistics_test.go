package enrollment

import (
	"strings"
	"testing"
	"time"

	"github.com/novakiosk/agent/printer"
)

func testPrinterStatistics(t *testing.T, identity Identity) PrinterStatistics {
	t.Helper()
	completion := "Wed Aug 26 12:30:00 2026"
	report := printer.Statistics{
		Version: printer.StatisticsVersion, Type: printer.StatisticsType, Source: printer.StatisticsSource,
		ObservedAt: "2026-08-24T12:34:56Z", ErrorCategory: nil, Truncated: false,
		Jobs: []printer.StatisticsJob{{QueueName: "zebra", JobKey: printer.StatisticsJobKey("zebra", 7, 10, completion), CUPSJobID: 7, SizeBytes: 10, CompletedAt: "2026-08-26T12:30:00Z"}},
	}
	hash, err := printer.StatisticsHash(report)
	if err != nil {
		t.Fatal(err)
	}
	envelope := PrinterStatistics{Version: ProtocolVersion, Type: PrinterStatisticsType, Profile: ProvisionalIdentityProfile, SessionID: "session-1", DeviceID: identity.DeviceID, Report: report, ReportHash: hash, Sequence: 1}
	signature, err := SignPrinterStatistics(identity, envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = signature
	return envelope
}

func TestPrinterStatisticsCanonicalSigningAndHashBinding(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope := testPrinterStatistics(t, identity)
	if err := ValidatePrinterStatistics(envelope, envelope.SessionID, identity.DeviceID); err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(identity.PublicIdentityRef, PrinterStatisticsCanonical(envelope), envelope.Signature) {
		t.Fatal("valid printer statistics signature rejected")
	}
	if !strings.Contains(string(PrinterStatisticsCanonical(envelope)), "type=cHJpbnRlci5zdGF0aXN0aWNz") {
		t.Fatal("printer statistics canonical domain is missing")
	}
	changed := envelope
	changed.Sequence++
	if VerifySignature(identity.PublicIdentityRef, PrinterStatisticsCanonical(changed), envelope.Signature) {
		t.Fatal("sequence change retained signature")
	}
	changed = envelope
	changed.ReportHash = strings.Repeat("0", 64)
	if ValidatePrinterStatistics(changed, changed.SessionID, changed.DeviceID) == nil {
		t.Fatal("mismatched report hash accepted")
	}
}

func TestPrinterStatisticsAcceptedBindingAndCadence(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope := testPrinterStatistics(t, identity)
	accepted := PrinterStatisticsAccepted{Version: ProtocolVersion, Type: "printer.statistics.accepted", SessionID: envelope.SessionID, DeviceID: envelope.DeviceID, ReportHash: envelope.ReportHash, Sequence: envelope.Sequence, Disposition: "accepted"}
	if err := ValidatePrinterStatisticsAccepted(accepted, envelope); err != nil {
		t.Fatal(err)
	}
	accepted.Disposition = "older"
	if err := ValidatePrinterStatisticsAccepted(accepted, envelope); err == nil {
		t.Fatal("older disposition accepted")
	}
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	state := State{LastPrinterStatisticsAccepted: true, LastPrinterStatisticsAttemptAt: now.Add(-29 * time.Second).Format(time.RFC3339Nano)}
	if printerStatisticsDue(state, now) {
		t.Fatal("accepted statistics was due before 30 seconds")
	}
	state.LastPrinterStatisticsAttemptAt = now.Add(-PrinterStatisticsMinInterval).Format(time.RFC3339Nano)
	if !printerStatisticsDue(state, now) {
		t.Fatal("accepted statistics was not due at 30 seconds")
	}
	state.LastPrinterStatisticsAttemptAt = now.Format(time.RFC3339Nano)
	state.LastPrinterStatisticsAccepted = false
	if !printerStatisticsDue(state, now) {
		t.Fatal("unaccepted response-loss marker did not force retry")
	}
}
