package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsjob"
)

const PrinterJobCommandCapability = "printer-job-command-v1"

var printerJobCommandUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var printerJobCommandHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var printerJobCommandTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)

type PrinterJobCanceler interface {
	Cancel(context.Context, cupsjob.Request) (cupsjob.Result, error)
}

type PrinterJobCommand struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	Profile       string `json:"profile"`
	CommandID     string `json:"commandId"`
	Action        string `json:"action"`
	AuthorityKind string `json:"authorityKind"`
	AuthorityID   string `json:"authorityId"`
	QueueName     string `json:"queueName"`
	CUPSJobID     uint64 `json:"cupsJobId"`
	JobKey        string `json:"jobKey"`
	IssuedAt      string `json:"issuedAt"`
	ExpiresAt     string `json:"expiresAt"`
	PayloadHash   string `json:"payloadHash"`
}

type PrinterJobCommandResult struct {
	Version       int     `json:"version"`
	Type          string  `json:"type"`
	Profile       string  `json:"profile"`
	SessionID     string  `json:"sessionId"`
	DeviceID      string  `json:"deviceId"`
	CommandID     string  `json:"commandId"`
	Action        string  `json:"action"`
	AuthorityKind string  `json:"authorityKind"`
	AuthorityID   string  `json:"authorityId"`
	QueueName     string  `json:"queueName"`
	CUPSJobID     uint64  `json:"cupsJobId"`
	JobKey        string  `json:"jobKey"`
	PayloadHash   string  `json:"payloadHash"`
	Result        string  `json:"result"`
	ErrorCategory *string `json:"errorCategory"`
	ObservedAt    string  `json:"observedAt"`
	Sequence      uint64  `json:"sequence"`
	Signature     string  `json:"signature"`
}

type PrinterJobCommandAccepted struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	DeviceID    string `json:"deviceId"`
	CommandID   string `json:"commandId"`
	PayloadHash string `json:"payloadHash"`
	Sequence    uint64 `json:"sequence"`
	Disposition string `json:"disposition"`
}

func PrinterJobCommandCanonical(command PrinterJobCommand) []byte {
	return CanonicalV1("printer.job.command",
		CanonicalField{"version", "1"}, CanonicalField{"profile", command.Profile},
		CanonicalField{"commandId", command.CommandID}, CanonicalField{"action", command.Action},
		CanonicalField{"authorityKind", command.AuthorityKind}, CanonicalField{"authorityId", command.AuthorityID},
		CanonicalField{"queueName", command.QueueName}, CanonicalField{"cupsJobId", fmt.Sprintf("%d", command.CUPSJobID)},
		CanonicalField{"jobKey", command.JobKey}, CanonicalField{"issuedAt", command.IssuedAt}, CanonicalField{"expiresAt", command.ExpiresAt})
}

func PrinterJobCommandHash(command PrinterJobCommand) string {
	digest := sha256.Sum256(PrinterJobCommandCanonical(command))
	return hex.EncodeToString(digest[:])
}

func PrinterJobCommandResultCanonical(result PrinterJobCommandResult) []byte {
	errorCategory := ""
	if result.ErrorCategory != nil {
		errorCategory = *result.ErrorCategory
	}
	return CanonicalV1("printer.job.command.result",
		CanonicalField{"version", "1"}, CanonicalField{"profile", result.Profile},
		CanonicalField{"sessionId", result.SessionID}, CanonicalField{"deviceId", result.DeviceID}, CanonicalField{"commandId", result.CommandID},
		CanonicalField{"action", result.Action}, CanonicalField{"authorityKind", result.AuthorityKind}, CanonicalField{"authorityId", result.AuthorityID},
		CanonicalField{"queueName", result.QueueName}, CanonicalField{"cupsJobId", fmt.Sprintf("%d", result.CUPSJobID)}, CanonicalField{"jobKey", result.JobKey},
		CanonicalField{"payloadHash", result.PayloadHash}, CanonicalField{"result", result.Result}, CanonicalField{"errorCategory", errorCategory},
		CanonicalField{"observedAt", result.ObservedAt}, CanonicalField{"sequence", fmt.Sprintf("%d", result.Sequence)})
}

func (command PrinterJobCommand) Validate(now time.Time, allowExpired bool) error {
	if command.Version != ProtocolVersion || command.Type != "printer.job.command" || !supportedIdentityProfile(command.Profile) || !printerJobCommandUUID.MatchString(command.CommandID) || command.Action != cupsjob.ActionCancel || (command.AuthorityKind != "managed-wireless" && command.AuthorityKind != "kiosk-usb") || !validPrinterJobCommandText(command.AuthorityID, 128) || !cupsjob.SafeQueueName(command.QueueName) || command.CUPSJobID < 1 || command.CUPSJobID > 2_147_483_647 || !printerJobCommandHashPattern.MatchString(command.JobKey) {
		return fmt.Errorf("printer job command identity is invalid")
	}
	issued, err := parsePrinterJobCommandTimestamp(command.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parsePrinterJobCommandTimestamp(command.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 15*time.Minute {
		return fmt.Errorf("printer job command expiry is invalid")
	}
	if !allowExpired && (now.After(expires.Add(5*time.Minute)) || now.Before(issued.Add(-5*time.Minute))) {
		return fmt.Errorf("printer job command is outside its time window")
	}
	if !printerJobCommandHashPattern.MatchString(command.PayloadHash) || PrinterJobCommandHash(command) != command.PayloadHash {
		return fmt.Errorf("printer job command hash is invalid")
	}
	return nil
}

func (result PrinterJobCommandResult) Validate() error {
	if result.Version != ProtocolVersion || result.Type != "printer.job.command.result" || !supportedIdentityProfile(result.Profile) || !validPrinterJobCommandText(result.SessionID, 128) || !validPrinterJobCommandText(result.DeviceID, 128) || !printerJobCommandUUID.MatchString(result.CommandID) || result.Action != cupsjob.ActionCancel || (result.AuthorityKind != "managed-wireless" && result.AuthorityKind != "kiosk-usb") || !validPrinterJobCommandText(result.AuthorityID, 128) || !cupsjob.SafeQueueName(result.QueueName) || result.CUPSJobID < 1 || result.CUPSJobID > 2_147_483_647 || !printerJobCommandHashPattern.MatchString(result.JobKey) || !printerJobCommandHashPattern.MatchString(result.PayloadHash) || (result.Result != cupsjob.ResultApplied && result.Result != cupsjob.ResultFailed) || result.ObservedAt == "" || result.Sequence == 0 || result.Signature == "" || len(result.Signature) > 256 {
		return fmt.Errorf("printer job command result is invalid")
	}
	if result.Result == cupsjob.ResultApplied && result.ErrorCategory != nil {
		return fmt.Errorf("applied printer job command has an error")
	}
	if result.Result == cupsjob.ResultFailed {
		if result.ErrorCategory == nil {
			return fmt.Errorf("failed printer job command has no error")
		}
		switch *result.ErrorCategory {
		case cupsjob.ErrorNotActive, cupsjob.ErrorPermission, cupsjob.ErrorHelper, cupsjob.ErrorTimeout, cupsjob.ErrorCommandFailed, cupsjob.ErrorInvalid, cupsjob.ErrorQueueNotAllowed:
		default:
			return fmt.Errorf("invalid printer job command error")
		}
	}
	if err := validatePrinterJobCommandTimestamp(result.ObservedAt); err != nil {
		return err
	}
	return nil
}

func parsePrinterJobCommandTimestamp(value string) (time.Time, error) {
	if !printerJobCommandTimestampPattern.MatchString(value) {
		return time.Time{}, fmt.Errorf("printer job command timestamp is invalid")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("printer job command timestamp is invalid")
	}
	return parsed, nil
}

func validatePrinterJobCommandTimestamp(value string) error {
	_, err := parsePrinterJobCommandTimestamp(value)
	return err
}

func validPrinterJobCommandText(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func SignPrinterJobCommandResult(identity Identity, result PrinterJobCommandResult) (string, error) {
	canonical := PrinterJobCommandResultCanonical(result)
	if len(canonical) == 0 {
		return "", fmt.Errorf("printer job command result canonical payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

func validPrinterJobAuthorityForKind(command PrinterJobCommand, kind DeviceKind) bool {
	return (kind == DeviceKindPrintServer && command.AuthorityKind == "managed-wireless") || (kind == DeviceKindKiosk && command.AuthorityKind == "kiosk-usb")
}

func (client Client) applyPrinterJobCommand(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, snapshot DesiredSnapshot, canceler PrinterJobCanceler) error {
	command := snapshot.PrinterJobCommand
	if command == nil {
		return nil
	}
	sameCommand := state.LastPrinterJobCommandID == command.CommandID && state.LastPrinterJobCommandHash == command.PayloadHash
	// A command whose result was durably recorded before the socket write must
	// remain replayable after its live window. New commands still require the
	// normal live window, while the hash/identity validation is always strict.
	if err := command.Validate(client.now(), sameCommand); err != nil || command.Profile != identity.Profile() || !validPrinterJobAuthorityForKind(*command, EffectiveDeviceKind(state.DeviceKind)) {
		return fmt.Errorf("printer job command is invalid")
	}
	if sameCommand && state.LastPrinterJobCommandAccepted {
		return nil
	}
	profile := "kiosk"
	if EffectiveDeviceKind(state.DeviceKind) == DeviceKindPrintServer {
		profile = "print-bridge"
	}
	// Once the result is persisted, reconnects replay it without rerunning the helper.
	replaying := sameCommand && state.LastPrinterJobCommandAt != "" && state.PrinterJobCommandSequence > 0 && state.LastPrinterJobCommandResult != ""
	var result PrinterJobCommandResult
	if replaying {
		result = PrinterJobCommandResult{Version: ProtocolVersion, Type: "printer.job.command.result", Profile: identity.Profile(), SessionID: snapshot.SessionID, DeviceID: state.DeviceID, CommandID: command.CommandID, Action: command.Action, AuthorityKind: command.AuthorityKind, AuthorityID: command.AuthorityID, QueueName: command.QueueName, CUPSJobID: command.CUPSJobID, JobKey: command.JobKey, PayloadHash: command.PayloadHash, Result: state.LastPrinterJobCommandResult, ObservedAt: state.LastPrinterJobCommandAt, Sequence: state.PrinterJobCommandSequence}
		if state.LastPrinterJobCommandError != "" {
			category := state.LastPrinterJobCommandError
			result.ErrorCategory = &category
		}
	} else {
		var helperResult cupsjob.Result
		if canceler == nil {
			helperResult = cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.ResultType, Profile: profile, Action: cupsjob.ActionCancel, CommandHash: command.PayloadHash, QueueName: command.QueueName, CUPSJobID: command.CUPSJobID, Result: cupsjob.ResultFailed, Error: cupsjob.ErrorHelper}
		} else {
			var helperErr error
			helperResult, helperErr = canceler.Cancel(ctx, cupsjob.Request{Version: cupsjob.Version, Type: cupsjob.RequestType, Profile: profile, Action: cupsjob.ActionCancel, CommandHash: command.PayloadHash, QueueName: command.QueueName, CUPSJobID: command.CUPSJobID})
			if helperErr != nil || helperResult.Validate(profile) != nil || helperResult.CommandHash != command.PayloadHash || helperResult.QueueName != command.QueueName || helperResult.CUPSJobID != command.CUPSJobID || helperResult.Action != command.Action {
				helperResult = cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.ResultType, Profile: profile, Action: cupsjob.ActionCancel, CommandHash: command.PayloadHash, QueueName: command.QueueName, CUPSJobID: command.CUPSJobID, Result: cupsjob.ResultFailed, Error: cupsjob.ErrorHelper}
			}
		}
		result = PrinterJobCommandResult{Version: ProtocolVersion, Type: "printer.job.command.result", Profile: identity.Profile(), SessionID: snapshot.SessionID, DeviceID: state.DeviceID, CommandID: command.CommandID, Action: command.Action, AuthorityKind: command.AuthorityKind, AuthorityID: command.AuthorityID, QueueName: command.QueueName, CUPSJobID: command.CUPSJobID, JobKey: command.JobKey, PayloadHash: command.PayloadHash, Result: helperResult.Result, ObservedAt: client.now().UTC().Format(time.RFC3339Nano), Sequence: state.PrinterJobCommandSequence + 1}
		if helperResult.Result != cupsjob.ResultApplied {
			result.Result = cupsjob.ResultFailed
			category := helperResult.Error
			if category == "" {
				category = cupsjob.ErrorHelper
			}
			result.ErrorCategory = &category
		}
	}
	var signErr error
	result.Signature, signErr = SignPrinterJobCommandResult(identity, result)
	if signErr != nil {
		return signErr
	}
	if err := result.Validate(); err != nil {
		return err
	}
	if !replaying {
		state.PrinterJobCommandSequence = result.Sequence
		state.LastPrinterJobCommandID = command.CommandID
		state.LastPrinterJobCommandHash = command.PayloadHash
		state.LastPrinterJobCommandResult = result.Result
		state.LastPrinterJobCommandError = ""
		if result.ErrorCategory != nil {
			state.LastPrinterJobCommandError = *result.ErrorCategory
		}
		state.LastPrinterJobCommandAt = result.ObservedAt
		state.LastPrinterJobCommandAccepted = false
		if err := SaveStateAtomic(client.StateDir, *state); err != nil {
			return err
		}
	}
	if err := writeSessionMessage(connection, result, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted PrinterJobCommandAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "printer.job.command.result.accepted" || accepted.SessionID != result.SessionID || accepted.DeviceID != result.DeviceID || accepted.CommandID != result.CommandID || accepted.PayloadHash != result.PayloadHash || accepted.Sequence != result.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("printer job command acknowledgement was not accepted")
	}
	state.LastPrinterJobCommandAccepted = true
	return SaveStateAtomic(client.StateDir, *state)
}
