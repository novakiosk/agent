package enrollment

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/printer"
)

const (
	PrinterReportType        = "printer.report"
	PrinterReportMaxAge      = 10 * time.Second
	PrinterReportMinInterval = 30 * time.Second
)

// PrinterReporter is the managed-run seam for local CUPS evidence. Probe
// failures are expected to be represented by printer.Report evidence rather
// than transport errors; the interface remains injectable for tests.
type PrinterReporter interface {
	Collect(context.Context) (printer.Report, error)
}

type PrinterReport struct {
	Version    int            `json:"version"`
	Type       string         `json:"type"`
	Profile    string         `json:"profile"`
	SessionID  string         `json:"sessionId"`
	DeviceID   string         `json:"deviceId"`
	Report     printer.Report `json:"report"`
	ReportHash string         `json:"reportHash"`
	Sequence   uint64         `json:"sequence"`
	Signature  string         `json:"signature"`
}

type PrinterReportAccepted struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	DeviceID    string `json:"deviceId"`
	ReportHash  string `json:"reportHash"`
	Sequence    uint64 `json:"sequence"`
	Disposition string `json:"disposition"`
}

func PrinterReportCanonical(report PrinterReport) []byte {
	return CanonicalV1(PrinterReportType,
		CanonicalField{"version", "1"},
		CanonicalField{"profile", report.Profile},
		CanonicalField{"sessionId", report.SessionID},
		CanonicalField{"deviceId", report.DeviceID},
		CanonicalField{"reportHash", report.ReportHash},
		CanonicalField{"sequence", fmt.Sprintf("%d", report.Sequence)},
	)
}

func SignPrinterReport(identity Identity, report PrinterReport) (string, error) {
	canonical := PrinterReportCanonical(report)
	if len(canonical) == 0 {
		return "", fmt.Errorf("printer report canonical payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

func ValidatePrinterReport(report PrinterReport, sessionID, deviceID string) error {
	if report.Version != ProtocolVersion || report.Type != PrinterReportType || !supportedIdentityProfile(report.Profile) || report.SessionID != sessionID || report.DeviceID != deviceID || report.Sequence == 0 {
		return fmt.Errorf("printer report envelope is invalid")
	}
	if err := ValidateDeviceID(report.DeviceID); err != nil {
		return fmt.Errorf("printer report device ID is invalid")
	}
	if report.SessionID == "" || len(report.SessionID) > 128 || strings.TrimSpace(report.SessionID) != report.SessionID {
		return fmt.Errorf("printer report session ID is invalid")
	}
	if err := report.Report.Validate(); err != nil {
		return fmt.Errorf("printer report evidence is invalid")
	}
	hash, err := printer.CanonicalPayloadHash(report.Report)
	if err != nil || len(report.ReportHash) != 64 || strings.Trim(report.ReportHash, "0123456789abcdef") != "" || hash != report.ReportHash {
		return fmt.Errorf("printer report hash is invalid")
	}
	if len(report.Signature) == 0 || len(report.Signature) > 256 {
		return fmt.Errorf("printer report signature is invalid")
	}
	return nil
}

func ValidatePrinterReportAccepted(accepted PrinterReportAccepted, expected PrinterReport) error {
	if accepted.Version != ProtocolVersion || accepted.Type != "printer.report.accepted" || accepted.SessionID != expected.SessionID || accepted.DeviceID != expected.DeviceID || accepted.ReportHash != expected.ReportHash || accepted.Sequence != expected.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("printer report acknowledgement was not accepted")
	}
	return nil
}

func printerReportDue(state State, now time.Time) bool {
	if !state.LastPrinterReportAccepted || state.LastPrinterReportAttemptAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339Nano, state.LastPrinterReportAttemptAt)
	if err != nil || now.Before(last) {
		return true
	}
	return now.Sub(last) >= PrinterReportMinInterval
}

func (client Client) sendPrinterReport(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, reporter PrinterReporter) error {
	probeCtx, cancel := context.WithTimeout(ctx, PrinterReportMaxAge)
	defer cancel()
	report, err := reporter.Collect(probeCtx)
	if err != nil {
		return fmt.Errorf("collect printer report")
	}
	reportHash, err := printer.CanonicalPayloadHash(report)
	if err != nil {
		return fmt.Errorf("hash printer report")
	}
	sequence := state.PrinterReportSequence + 1
	envelope := PrinterReport{
		Version: ProtocolVersion, Type: PrinterReportType, Profile: identity.Profile(),
		SessionID: sessionID, DeviceID: state.DeviceID, Report: report, ReportHash: reportHash, Sequence: sequence,
	}
	envelope.Signature, err = SignPrinterReport(identity, envelope)
	if err != nil {
		return err
	}
	if err := ValidatePrinterReport(envelope, sessionID, state.DeviceID); err != nil {
		return err
	}
	attemptedAt := client.now().UTC().Format(time.RFC3339Nano)
	state.PrinterReportSequence = sequence
	state.LastPrinterReportHash = reportHash
	state.LastPrinterReportAttemptAt = attemptedAt
	state.LastPrinterReportAccepted = false
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, envelope, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted PrinterReportAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if err := ValidatePrinterReportAccepted(accepted, envelope); err != nil {
		return err
	}
	state.LastPrinterReportAccepted = true
	return SaveStateAtomic(client.StateDir, *state)
}
