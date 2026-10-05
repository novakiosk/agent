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
	PrinterStatisticsType        = "printer.statistics"
	PrinterStatisticsMaxAge      = 10 * time.Second
	PrinterStatisticsMinInterval = 30 * time.Second
	PrinterStatisticsCapability  = "printer-statistics-v1"
)

type PrinterStatisticsReporter interface {
	Collect(context.Context) (printer.Statistics, error)
}

type PrinterStatistics struct {
	Version    int                `json:"version"`
	Type       string             `json:"type"`
	Profile    string             `json:"profile"`
	SessionID  string             `json:"sessionId"`
	DeviceID   string             `json:"deviceId"`
	Report     printer.Statistics `json:"report"`
	ReportHash string             `json:"reportHash"`
	Sequence   uint64             `json:"sequence"`
	Signature  string             `json:"signature"`
}

type PrinterStatisticsAccepted struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	DeviceID    string `json:"deviceId"`
	ReportHash  string `json:"reportHash"`
	Sequence    uint64 `json:"sequence"`
	Disposition string `json:"disposition"`
}

func PrinterStatisticsCanonical(report PrinterStatistics) []byte {
	return CanonicalV1(PrinterStatisticsType,
		CanonicalField{"version", "1"},
		CanonicalField{"profile", report.Profile},
		CanonicalField{"sessionId", report.SessionID},
		CanonicalField{"deviceId", report.DeviceID},
		CanonicalField{"reportHash", report.ReportHash},
		CanonicalField{"sequence", fmt.Sprintf("%d", report.Sequence)},
	)
}

func SignPrinterStatistics(identity Identity, report PrinterStatistics) (string, error) {
	canonical := PrinterStatisticsCanonical(report)
	if len(canonical) == 0 {
		return "", fmt.Errorf("printer statistics canonical payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

func ValidatePrinterStatistics(report PrinterStatistics, sessionID, deviceID string) error {
	if report.Version != ProtocolVersion || report.Type != PrinterStatisticsType || !supportedIdentityProfile(report.Profile) || report.SessionID != sessionID || report.DeviceID != deviceID || report.Sequence == 0 {
		return fmt.Errorf("printer statistics envelope is invalid")
	}
	if err := ValidateDeviceID(report.DeviceID); err != nil {
		return fmt.Errorf("printer statistics device ID is invalid")
	}
	if report.SessionID == "" || len(report.SessionID) > 128 || strings.TrimSpace(report.SessionID) != report.SessionID {
		return fmt.Errorf("printer statistics session ID is invalid")
	}
	if err := report.Report.Validate(); err != nil {
		return fmt.Errorf("printer statistics evidence is invalid")
	}
	hash, err := printer.StatisticsHash(report.Report)
	if err != nil || len(report.ReportHash) != 64 || strings.Trim(report.ReportHash, "0123456789abcdef") != "" || hash != report.ReportHash {
		return fmt.Errorf("printer statistics hash is invalid")
	}
	if len(report.Signature) == 0 || len(report.Signature) > 256 {
		return fmt.Errorf("printer statistics signature is invalid")
	}
	return nil
}

func ValidatePrinterStatisticsAccepted(accepted PrinterStatisticsAccepted, expected PrinterStatistics) error {
	if accepted.Version != ProtocolVersion || accepted.Type != "printer.statistics.accepted" || accepted.SessionID != expected.SessionID || accepted.DeviceID != expected.DeviceID || accepted.ReportHash != expected.ReportHash || accepted.Sequence != expected.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("printer statistics acknowledgement was not accepted")
	}
	return nil
}

func printerStatisticsDue(state State, now time.Time) bool {
	if !state.LastPrinterStatisticsAccepted || state.LastPrinterStatisticsAttemptAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339Nano, state.LastPrinterStatisticsAttemptAt)
	if err != nil || now.Before(last) {
		return true
	}
	return now.Sub(last) >= PrinterStatisticsMinInterval
}

func (client Client) sendPrinterStatistics(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, reporter PrinterStatisticsReporter) error {
	probeCtx, cancel := context.WithTimeout(ctx, PrinterStatisticsMaxAge)
	defer cancel()
	report, err := reporter.Collect(probeCtx)
	if err != nil {
		return fmt.Errorf("collect printer statistics")
	}
	reportHash, err := printer.StatisticsHash(report)
	if err != nil {
		return fmt.Errorf("hash printer statistics")
	}
	sequence := state.PrinterStatisticsSequence + 1
	envelope := PrinterStatistics{Version: ProtocolVersion, Type: PrinterStatisticsType, Profile: identity.Profile(), SessionID: sessionID, DeviceID: state.DeviceID, Report: report, ReportHash: reportHash, Sequence: sequence}
	envelope.Signature, err = SignPrinterStatistics(identity, envelope)
	if err != nil {
		return err
	}
	if err := ValidatePrinterStatistics(envelope, sessionID, state.DeviceID); err != nil {
		return err
	}
	state.PrinterStatisticsSequence = sequence
	state.LastPrinterStatisticsHash = reportHash
	state.LastPrinterStatisticsAttemptAt = client.now().UTC().Format(time.RFC3339Nano)
	state.LastPrinterStatisticsAccepted = false
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, envelope, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted PrinterStatisticsAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if err := ValidatePrinterStatisticsAccepted(accepted, envelope); err != nil {
		return err
	}
	state.LastPrinterStatisticsAccepted = true
	return SaveStateAtomic(client.StateDir, *state)
}
