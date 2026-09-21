package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsjob"
)

const PrinterQueueCommandCapability = "printer-queue-command-v1"

type PrinterQueueController interface {
	ControlQueue(context.Context, cupsjob.Request) (cupsjob.Result, error)
}

type PrinterQueueCommand struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	Profile       string `json:"profile"`
	CommandID     string `json:"commandId"`
	Action        string `json:"action"`
	AuthorityKind string `json:"authorityKind"`
	AuthorityID   string `json:"authorityId"`
	QueueName     string `json:"queueName"`
	IssuedAt      string `json:"issuedAt"`
	ExpiresAt     string `json:"expiresAt"`
	PayloadHash   string `json:"payloadHash"`
}

type PrinterQueueCommandResult struct {
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
	PayloadHash   string  `json:"payloadHash"`
	Result        string  `json:"result"`
	ErrorCategory *string `json:"errorCategory"`
	AffectedJobs  *uint64 `json:"affectedJobs"`
	ObservedAt    string  `json:"observedAt"`
	Sequence      uint64  `json:"sequence"`
	Signature     string  `json:"signature"`
}

type PrinterQueueCommandAccepted struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	DeviceID    string `json:"deviceId"`
	CommandID   string `json:"commandId"`
	PayloadHash string `json:"payloadHash"`
	Sequence    uint64 `json:"sequence"`
	Disposition string `json:"disposition"`
}

func PrinterQueueCommandCanonical(command PrinterQueueCommand) []byte {
	return CanonicalV1("printer.queue.command",
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"commandId", command.CommandID}, CanonicalField{"action", command.Action},
		CanonicalField{"authorityKind", command.AuthorityKind}, CanonicalField{"authorityId", command.AuthorityID},
		CanonicalField{"queueName", command.QueueName}, CanonicalField{"issuedAt", command.IssuedAt}, CanonicalField{"expiresAt", command.ExpiresAt})
}

func PrinterQueueCommandHash(command PrinterQueueCommand) string {
	digest := sha256.Sum256(PrinterQueueCommandCanonical(command))
	return hex.EncodeToString(digest[:])
}

func PrinterQueueCommandResultCanonical(result PrinterQueueCommandResult) []byte {
	errorCategory, affectedJobs := "", ""
	if result.ErrorCategory != nil {
		errorCategory = *result.ErrorCategory
	}
	if result.AffectedJobs != nil {
		affectedJobs = fmt.Sprintf("%d", *result.AffectedJobs)
	}
	return CanonicalV1("printer.queue.command.result",
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", result.SessionID}, CanonicalField{"deviceId", result.DeviceID}, CanonicalField{"commandId", result.CommandID},
		CanonicalField{"action", result.Action}, CanonicalField{"authorityKind", result.AuthorityKind}, CanonicalField{"authorityId", result.AuthorityID},
		CanonicalField{"queueName", result.QueueName}, CanonicalField{"payloadHash", result.PayloadHash}, CanonicalField{"result", result.Result},
		CanonicalField{"errorCategory", errorCategory}, CanonicalField{"affectedJobs", affectedJobs}, CanonicalField{"observedAt", result.ObservedAt},
		CanonicalField{"sequence", fmt.Sprintf("%d", result.Sequence)})
}

func validPrinterQueueAction(action string) bool {
	return action == cupsjob.ActionPause || action == cupsjob.ActionResume || action == cupsjob.ActionCancelAll || action == cupsjob.ActionDelete || action == cupsjob.ActionAddUSB
}

func (command PrinterQueueCommand) Validate(now time.Time, allowExpired bool) error {
	if command.Version != ProtocolVersion || command.Type != "printer.queue.command" || command.Profile != ProvisionalIdentityProfile || !printerJobCommandUUID.MatchString(command.CommandID) || !validPrinterQueueAction(command.Action) || (command.AuthorityKind != "managed-wireless" && command.AuthorityKind != "kiosk-usb") || !validPrinterJobCommandText(command.AuthorityID, 128) || !cupsjob.SafeQueueName(command.QueueName) {
		return fmt.Errorf("printer queue command identity is invalid")
	}
	issued, err := parsePrinterJobCommandTimestamp(command.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parsePrinterJobCommandTimestamp(command.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 15*time.Minute {
		return fmt.Errorf("printer queue command expiry is invalid")
	}
	if !allowExpired && (now.After(expires.Add(5*time.Minute)) || now.Before(issued.Add(-5*time.Minute))) {
		return fmt.Errorf("printer queue command is outside its time window")
	}
	if !printerJobCommandHashPattern.MatchString(command.PayloadHash) || PrinterQueueCommandHash(command) != command.PayloadHash {
		return fmt.Errorf("printer queue command hash is invalid")
	}
	return nil
}

func (result PrinterQueueCommandResult) Validate() error {
	if result.Version != ProtocolVersion || result.Type != "printer.queue.command.result" || result.Profile != ProvisionalIdentityProfile || !validPrinterJobCommandText(result.SessionID, 128) || !validPrinterJobCommandText(result.DeviceID, 128) || !printerJobCommandUUID.MatchString(result.CommandID) || !validPrinterQueueAction(result.Action) || (result.AuthorityKind != "managed-wireless" && result.AuthorityKind != "kiosk-usb") || !validPrinterJobCommandText(result.AuthorityID, 128) || !cupsjob.SafeQueueName(result.QueueName) || !printerJobCommandHashPattern.MatchString(result.PayloadHash) || (result.Result != cupsjob.ResultApplied && result.Result != cupsjob.ResultFailed) || result.ObservedAt == "" || result.Sequence == 0 || result.Signature == "" || len(result.Signature) > 256 {
		return fmt.Errorf("printer queue command result is invalid")
	}
	if result.Action == cupsjob.ActionCancelAll {
		if result.AffectedJobs == nil || *result.AffectedJobs > 4096 {
			return fmt.Errorf("printer queue command affected job count is invalid")
		}
	} else if result.AffectedJobs != nil {
		return fmt.Errorf("printer queue state command has an affected job count")
	}
	if result.Result == cupsjob.ResultApplied && result.ErrorCategory != nil {
		return fmt.Errorf("applied printer queue command has an error")
	}
	if result.Result == cupsjob.ResultFailed {
		if result.ErrorCategory == nil {
			return fmt.Errorf("failed printer queue command has no error")
		}
		switch *result.ErrorCategory {
		case cupsjob.ErrorPermission, cupsjob.ErrorHelper, cupsjob.ErrorTimeout, cupsjob.ErrorCommandFailed, cupsjob.ErrorInvalid, cupsjob.ErrorQueueNotAllowed:
		default:
			return fmt.Errorf("invalid printer queue command error")
		}
	}
	return validatePrinterJobCommandTimestamp(result.ObservedAt)
}

func SignPrinterQueueCommandResult(identity Identity, result PrinterQueueCommandResult) (string, error) {
	canonical := PrinterQueueCommandResultCanonical(result)
	if len(canonical) == 0 {
		return "", fmt.Errorf("printer queue command result canonical payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

func validPrinterQueueAuthorityForKind(command PrinterQueueCommand, kind DeviceKind) bool {
	if (command.Action == cupsjob.ActionDelete || command.Action == cupsjob.ActionAddUSB) && command.AuthorityKind != "kiosk-usb" {
		return false
	}
	return (kind == DeviceKindPrintServer && command.AuthorityKind == "managed-wireless") || (kind == DeviceKindKiosk && command.AuthorityKind == "kiosk-usb")
}

func (client Client) applyPrinterQueueCommand(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, snapshot DesiredSnapshot, controller PrinterQueueController) error {
	command := snapshot.PrinterQueueCommand
	if command == nil {
		return nil
	}
	sameCommand := state.LastPrinterQueueCommandID == command.CommandID && state.LastPrinterQueueCommandHash == command.PayloadHash
	if err := command.Validate(client.now(), sameCommand); err != nil || !validPrinterQueueAuthorityForKind(*command, EffectiveDeviceKind(state.DeviceKind)) {
		return fmt.Errorf("printer queue command is invalid")
	}
	if sameCommand && state.LastPrinterQueueCommandAccepted {
		return nil
	}
	profile := "kiosk"
	if EffectiveDeviceKind(state.DeviceKind) == DeviceKindPrintServer {
		profile = "print-bridge"
	}
	replaying := sameCommand && state.LastPrinterQueueCommandAt != "" && state.PrinterQueueCommandSequence > 0 && state.LastPrinterQueueCommandResult != ""
	saveResult := func(result *PrinterQueueCommandResult) error {
		var err error
		result.Signature, err = SignPrinterQueueCommandResult(identity, *result)
		if err != nil {
			return err
		}
		if err := result.Validate(); err != nil {
			return err
		}
		pending := *state
		pending.PrinterQueueCommandSequence = result.Sequence
		pending.LastPrinterQueueCommandID = result.CommandID
		pending.LastPrinterQueueCommandHash = result.PayloadHash
		pending.LastPrinterQueueCommandResult = result.Result
		pending.LastPrinterQueueCommandError = ""
		if result.ErrorCategory != nil {
			pending.LastPrinterQueueCommandError = *result.ErrorCategory
		}
		pending.LastPrinterQueueCommandAffectedJobs = 0
		if result.AffectedJobs != nil {
			pending.LastPrinterQueueCommandAffectedJobs = *result.AffectedJobs
		}
		pending.LastPrinterQueueCommandAt = result.ObservedAt
		pending.LastPrinterQueueCommandAccepted = false
		if err := SaveStateAtomic(client.StateDir, pending); err != nil {
			return err
		}
		*state = pending
		return nil
	}
	var result PrinterQueueCommandResult
	if replaying {
		result = PrinterQueueCommandResult{Version: ProtocolVersion, Type: "printer.queue.command.result", Profile: ProvisionalIdentityProfile, SessionID: snapshot.SessionID, DeviceID: state.DeviceID, CommandID: command.CommandID, Action: command.Action, AuthorityKind: command.AuthorityKind, AuthorityID: command.AuthorityID, QueueName: command.QueueName, PayloadHash: command.PayloadHash, Result: state.LastPrinterQueueCommandResult, ObservedAt: state.LastPrinterQueueCommandAt, Sequence: state.PrinterQueueCommandSequence}
		if state.LastPrinterQueueCommandError != "" {
			category := state.LastPrinterQueueCommandError
			result.ErrorCategory = &category
		}
		if command.Action == cupsjob.ActionCancelAll {
			affected := state.LastPrinterQueueCommandAffectedJobs
			result.AffectedJobs = &affected
		}
	} else {
		// Persist a conservative outcome before the helper can affect jobs.
		// A crash or failed final save replays this failure at the same sequence.
		category := cupsjob.ErrorHelper
		result = PrinterQueueCommandResult{Version: ProtocolVersion, Type: "printer.queue.command.result", Profile: ProvisionalIdentityProfile, SessionID: snapshot.SessionID, DeviceID: state.DeviceID, CommandID: command.CommandID, Action: command.Action, AuthorityKind: command.AuthorityKind, AuthorityID: command.AuthorityID, QueueName: command.QueueName, PayloadHash: command.PayloadHash, Result: cupsjob.ResultFailed, ErrorCategory: &category, ObservedAt: client.now().UTC().Format(time.RFC3339Nano), Sequence: state.PrinterQueueCommandSequence + 1}
		if command.Action == cupsjob.ActionCancelAll {
			zero := uint64(0)
			result.AffectedJobs = &zero
		}
		if err := saveResult(&result); err != nil {
			return err
		}
		request := cupsjob.Request{Version: cupsjob.Version, Type: cupsjob.QueueRequestType, Profile: profile, Action: command.Action, CommandHash: command.PayloadHash, QueueName: command.QueueName}
		var helperResult cupsjob.Result
		if controller == nil {
			helperResult = failedPrinterQueueHelperResult(request)
		} else {
			var helperErr error
			helperResult, helperErr = controller.ControlQueue(ctx, request)
			if helperErr != nil || helperResult.Validate(profile) != nil || helperResult.CommandHash != command.PayloadHash || helperResult.QueueName != command.QueueName || helperResult.Action != command.Action {
				helperResult = failedPrinterQueueHelperResult(request)
			}
		}
		result.Result = helperResult.Result
		result.AffectedJobs = helperResult.AffectedJobs
		result.ObservedAt = client.now().UTC().Format(time.RFC3339Nano)
		result.ErrorCategory = nil
		if helperResult.Result != cupsjob.ResultApplied {
			result.Result = cupsjob.ResultFailed
			category := helperResult.Error
			if category == "" {
				category = cupsjob.ErrorHelper
			}
			result.ErrorCategory = &category
		}
	}
	if replaying {
		var err error
		result.Signature, err = SignPrinterQueueCommandResult(identity, result)
		if err != nil {
			return err
		}
		if err := result.Validate(); err != nil {
			return err
		}
	} else if err := saveResult(&result); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, result, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted PrinterQueueCommandAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "printer.queue.command.result.accepted" || accepted.SessionID != result.SessionID || accepted.DeviceID != result.DeviceID || accepted.CommandID != result.CommandID || accepted.PayloadHash != result.PayloadHash || accepted.Sequence != result.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("printer queue command acknowledgement was not accepted")
	}
	state.LastPrinterQueueCommandAccepted = true
	return SaveStateAtomic(client.StateDir, *state)
}

func failedPrinterQueueHelperResult(request cupsjob.Request) cupsjob.Result {
	result := cupsjob.Result{Version: cupsjob.Version, Type: cupsjob.QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: cupsjob.ResultFailed, Error: cupsjob.ErrorHelper}
	if request.Action == cupsjob.ActionCancelAll {
		zero := uint64(0)
		result.AffectedJobs = &zero
	}
	return result
}
