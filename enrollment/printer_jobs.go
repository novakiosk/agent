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
	PrinterJobsType        = "printer.jobs"
	PrinterJobsMaxAge      = 10 * time.Second
	PrinterJobsMinInterval = 15 * time.Second
	PrinterJobsCapability  = "printer-jobs-v1"
)

type PrinterJobsReporter interface {
	Collect(context.Context) (printer.Jobs, error)
}

type PrinterJobsReport struct {
	Version    int          `json:"version"`
	Type       string       `json:"type"`
	Profile    string       `json:"profile"`
	SessionID  string       `json:"sessionId"`
	DeviceID   string       `json:"deviceId"`
	Report     printer.Jobs `json:"report"`
	ReportHash string       `json:"reportHash"`
	Sequence   uint64       `json:"sequence"`
	Signature  string       `json:"signature"`
}

type PrinterJobsAccepted struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	DeviceID    string `json:"deviceId"`
	ReportHash  string `json:"reportHash"`
	Sequence    uint64 `json:"sequence"`
	Disposition string `json:"disposition"`
}

func PrinterJobsCanonical(report PrinterJobsReport) []byte {
	return CanonicalV1(PrinterJobsType,
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", report.SessionID},
		CanonicalField{"deviceId", report.DeviceID},
		CanonicalField{"reportHash", report.ReportHash},
		CanonicalField{"sequence", fmt.Sprintf("%d", report.Sequence)},
	)
}

func SignPrinterJobs(identity Identity, report PrinterJobsReport) (string, error) {
	canonical := PrinterJobsCanonical(report)
	if len(canonical) == 0 {
		return "", fmt.Errorf("printer jobs canonical payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

func ValidatePrinterJobs(report PrinterJobsReport, sessionID, deviceID string) error {
	if report.Version != ProtocolVersion || report.Type != PrinterJobsType || report.Profile != ProvisionalIdentityProfile || report.SessionID != sessionID || report.DeviceID != deviceID || report.Sequence == 0 {
		return fmt.Errorf("printer jobs envelope is invalid")
	}
	if err := ValidateDeviceID(report.DeviceID); err != nil {
		return fmt.Errorf("printer jobs device ID is invalid")
	}
	if report.SessionID == "" || len(report.SessionID) > 128 || strings.TrimSpace(report.SessionID) != report.SessionID {
		return fmt.Errorf("printer jobs session ID is invalid")
	}
	if err := report.Report.Validate(); err != nil {
		return fmt.Errorf("printer jobs evidence is invalid")
	}
	hash, err := printer.JobsHash(report.Report)
	if err != nil || len(report.ReportHash) != 64 || strings.Trim(report.ReportHash, "0123456789abcdef") != "" || hash != report.ReportHash {
		return fmt.Errorf("printer jobs hash is invalid")
	}
	if len(report.Signature) == 0 || len(report.Signature) > 256 {
		return fmt.Errorf("printer jobs signature is invalid")
	}
	return nil
}

func ValidatePrinterJobsAccepted(accepted PrinterJobsAccepted, expected PrinterJobsReport) error {
	if accepted.Version != ProtocolVersion || accepted.Type != PrinterJobsType+".accepted" || accepted.SessionID != expected.SessionID || accepted.DeviceID != expected.DeviceID || accepted.ReportHash != expected.ReportHash || accepted.Sequence != expected.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("printer jobs acknowledgement was not accepted")
	}
	return nil
}

func printerJobsDue(state State, now time.Time) bool {
	if !state.LastPrinterJobsAccepted || state.LastPrinterJobsAttemptAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339Nano, state.LastPrinterJobsAttemptAt)
	if err != nil || now.Before(last) {
		return true
	}
	return now.Sub(last) >= PrinterJobsMinInterval
}

func (client Client) sendPrinterJobs(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, reporter PrinterJobsReporter) error {
	probeCtx, cancel := context.WithTimeout(ctx, PrinterJobsMaxAge)
	defer cancel()
	report, err := reporter.Collect(probeCtx)
	if err != nil {
		return fmt.Errorf("collect printer jobs")
	}
	reportHash, err := printer.JobsHash(report)
	if err != nil {
		return fmt.Errorf("hash printer jobs")
	}
	sequence := state.PrinterJobsSequence + 1
	envelope := PrinterJobsReport{Version: ProtocolVersion, Type: PrinterJobsType, Profile: ProvisionalIdentityProfile, SessionID: sessionID, DeviceID: state.DeviceID, Report: report, ReportHash: reportHash, Sequence: sequence}
	envelope.Signature, err = SignPrinterJobs(identity, envelope)
	if err != nil {
		return err
	}
	if err := ValidatePrinterJobs(envelope, sessionID, state.DeviceID); err != nil {
		return err
	}
	attemptedAt := client.now().UTC().Format(time.RFC3339Nano)
	state.PrinterJobsSequence = sequence
	state.LastPrinterJobsHash = reportHash
	state.LastPrinterJobsAttemptAt = attemptedAt
	state.LastPrinterJobsAccepted = false
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, envelope, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted PrinterJobsAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if err := ValidatePrinterJobsAccepted(accepted, envelope); err != nil {
		return err
	}
	state.LastPrinterJobsAccepted = true
	return SaveStateAtomic(client.StateDir, *state)
}
