package enrollment

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsreconcile"
)

type printerDesiredAckAccepted struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	DeviceID    string `json:"deviceId"`
	DesiredHash string `json:"desiredHash"`
	Result      string `json:"result"`
	Sequence    uint64 `json:"sequence"`
	Disposition string `json:"disposition"`
}

func (client Client) receiveApplyAndAcknowledgePrinterDesired(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, applier cupsreconcile.Applier) error {
	var raw json.RawMessage
	if err := readSessionMessageBounded(ctx, connection, &raw, cupsreconcile.MaxMessageBytes); err != nil {
		return err
	}
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("printer desired state is invalid")
	}
	if envelope.Version == cupsreconcile.Version2 {
		desired, decodeErr := cupsreconcile.DecodeDesiredV2(raw, sessionID, state.DeviceID)
		if decodeErr != nil {
			return fmt.Errorf("printer desired v2 state is invalid")
		}
		directApplier, ok := applier.(cupsreconcile.DirectApplier)
		if !ok {
			return fmt.Errorf("direct printer reconciler is unavailable")
		}
		result := cupsreconcile.HelperResult{Version: cupsreconcile.Version2, Type: "printer.helper.result", DesiredHash: desired.DesiredHash, Result: cupsreconcile.ResultApplied}
		if state.PrinterDesiredHash != desired.DesiredHash || state.LastPrinterReconcileResult != cupsreconcile.ResultApplied {
			result = directApplier.ApplyV2(ctx, desired)
		}
		if result.DesiredHash != desired.DesiredHash || !validPrinterReconcileResult(result.Result, result.ErrorCategory) {
			result = cupsreconcile.HelperResult{Version: cupsreconcile.Version2, Type: "printer.helper.result", DesiredHash: desired.DesiredHash, Result: cupsreconcile.ResultFailed, ErrorCategory: cupsreconcile.ErrorHelper}
		}
		return client.sendPrinterReconcileAck(ctx, state, identity, connection, sessionID, desired.DesiredHash, result, cupsreconcile.Version2)
	}
	desired, decodeErr := cupsreconcile.DecodeDesired(raw, sessionID, state.DeviceID)
	if decodeErr != nil {
		return fmt.Errorf("printer desired state is invalid")
	}
	result := cupsreconcile.HelperResult{Version: cupsreconcile.Version, Type: "printer.helper.result", DesiredHash: desired.DesiredHash, Result: cupsreconcile.ResultApplied}
	queuesOnly := desired
	queuesOnly.DefaultQueue = nil
	queuesHash, _ := queuesOnly.PayloadHash()
	// Default-only changes must not recreate, enable, or probe remote queues.
	// Legacy failed ACKs cannot distinguish partial queue changes from default
	// failures. Reapply once; explicit false preserves new default-only failures.
	queuesUncertain := state.PrinterQueuesApplyPending != nil && *state.PrinterQueuesApplyPending || state.PrinterQueuesApplyPending == nil && state.LastPrinterReconcileResult == cupsreconcile.ResultFailed
	queuesApplied := !queuesUncertain && (state.PrinterQueuesAppliedHash == queuesHash || state.PrinterQueuesAppliedHash == "" && state.PrinterDesiredHash == desired.DesiredHash && state.LastPrinterReconcileResult == cupsreconcile.ResultApplied)
	if !queuesApplied {
		// Apply may partially mutate CUPS before failing or being interrupted.
		// Invalidate both cached and legacy success evidence durably first.
		pending := true
		state.PrinterQueuesApplyPending = &pending
		state.PrinterQueuesAppliedHash = ""
		if err := SaveStateAtomic(client.StateDir, *state); err != nil {
			return err
		}
		result = applier.Apply(ctx, desired)
		if result.DesiredHash != desired.DesiredHash || !validPrinterReconcileResult(result.Result, result.ErrorCategory) {
			result = cupsreconcile.HelperResult{Version: cupsreconcile.Version, Type: "printer.helper.result", DesiredHash: desired.DesiredHash, Result: cupsreconcile.ResultFailed, ErrorCategory: cupsreconcile.ErrorHelper}
		}
	}
	if result.Result == cupsreconcile.ResultApplied {
		state.PrinterQueuesAppliedHash = queuesHash
		pending := false
		state.PrinterQueuesApplyPending = &pending
	}
	// Reassert the user default even for an unchanged desired hash: browser or
	// operator choices must not silently become permanent kiosk defaults.
	if desired.DefaultQueue != nil && EffectiveDeviceKind(state.DeviceKind) == DeviceKindKiosk && result.Result == cupsreconcile.ResultApplied {
		maintainer, ok := applier.(interface {
			MaintainDefault(context.Context, cupsreconcile.Desired) error
		})
		if !ok || maintainer.MaintainDefault(ctx, desired) != nil {
			result.Result, result.ErrorCategory = cupsreconcile.ResultFailed, cupsreconcile.ErrorApply
		}
	}
	return client.sendPrinterReconcileAck(ctx, state, identity, connection, sessionID, desired.DesiredHash, result, cupsreconcile.Version)
}

func (client Client) sendPrinterReconcileAck(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID, desiredHash string, result cupsreconcile.HelperResult, version int) error {
	state.PrinterAckSequence++
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	ack := cupsreconcile.Ack{Version: version, Type: cupsreconcile.AckType, Profile: identity.Profile(), SessionID: sessionID, DeviceID: state.DeviceID, DesiredHash: desiredHash, Result: result.Result, ErrorCategory: result.ErrorCategory, ObservedAt: observedAt, Sequence: state.PrinterAckSequence}
	canonical := cupsreconcile.AckCanonical(ack)
	if version == cupsreconcile.Version2 {
		canonical = cupsreconcile.AckCanonicalV2(ack)
	}
	signature, err := encodeIdentitySignature(identity, canonical)
	if err != nil {
		return err
	}
	ack.Signature = signature
	state.PrinterDesiredHash = desiredHash
	state.LastPrinterReconcileResult = result.Result
	state.LastPrinterReconcileError = result.ErrorCategory
	state.LastPrinterReconcileAt = observedAt
	state.LastPrinterReconcileAccepted = false
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, ack, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted printerDesiredAckAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != version || accepted.Type != "printer.desired.ack.accepted" || accepted.SessionID != sessionID || accepted.DeviceID != state.DeviceID || accepted.DesiredHash != desiredHash || accepted.Result != result.Result || accepted.Sequence != ack.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate" && accepted.Disposition != "stale") {
		return fmt.Errorf("printer desired acknowledgement was not accepted")
	}
	state.LastPrinterReconcileAccepted = accepted.Disposition != "stale"
	return SaveStateAtomic(client.StateDir, *state)
}

func validPrinterReconcileResult(result, category string) bool {
	if result == cupsreconcile.ResultApplied {
		return category == ""
	}
	if result != cupsreconcile.ResultFailed {
		return false
	}
	switch category {
	case cupsreconcile.ErrorApply, cupsreconcile.ErrorHelper, cupsreconcile.ErrorInvalid, cupsreconcile.ErrorEndpoint:
		return true
	default:
		return false
	}
}
