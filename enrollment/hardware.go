package enrollment

import (
	"context"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/operations"
)

type inventoryAcceptedMessage struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	SessionID     string `json:"sessionId"`
	DeviceID      string `json:"deviceId"`
	InventoryHash string `json:"inventoryHash"`
	Sequence      uint64 `json:"sequence"`
	Disposition   string `json:"disposition"`
}

type operationAcceptedMessage struct {
	Version     int                    `json:"version"`
	Type        string                 `json:"type"`
	SessionID   string                 `json:"sessionId"`
	DeviceID    string                 `json:"deviceId"`
	CommandID   string                 `json:"commandId"`
	CommandType operations.CommandType `json:"commandType"`
	PayloadHash string                 `json:"payloadHash"`
	Result      string                 `json:"result"`
	Sequence    uint64                 `json:"sequence"`
	Disposition string                 `json:"disposition"`
}

func (client Client) handleHardwareSnapshot(
	ctx context.Context,
	state *State,
	identity Identity,
	connection *websocket.Conn,
	snapshot DesiredSnapshot,
	collector *operations.InventoryCollector,
	coordinator *operations.Coordinator,
	writeTimeout time.Duration,
) error {
	if err := client.sendInventoryIfNeeded(ctx, state, identity, connection, collector, writeTimeout); err != nil {
		return err
	}
	current, phase, present, err := coordinator.CurrentCommand()
	if err != nil {
		return fmt.Errorf("operation state unavailable")
	}
	if present && phase == operations.PhaseExecuted && (snapshot.Operation == nil || current.CommandID != snapshot.Operation.CommandID) {
		if err := client.replayOperationResult(ctx, state, identity, connection, coordinator, current, writeTimeout); err != nil {
			return err
		}
	}
	if snapshot.Operation == nil {
		return nil
	}
	return client.handleOperationCommand(ctx, state, identity, connection, *snapshot.Operation, coordinator, writeTimeout)
}

func (client Client) sendInventoryIfNeeded(
	ctx context.Context,
	state *State,
	identity Identity,
	connection *websocket.Conn,
	collector *operations.InventoryCollector,
	writeTimeout time.Duration,
) error {
	inventory, inventoryHash, sequence, needed, err := prepareInventoryReport(state, collector)
	if err != nil {
		if err == ErrPendingInventoryCorrupt {
			return err
		}
		// Inventory collection is evidence, not a reason to lose the
		// authenticated session. Doctor and the admin surface the missing
		// evidence separately; pending reports still fail closed and retry.
		return nil
	}
	if !needed {
		return nil
	}
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return fmt.Errorf("persist host inventory")
	}
	report := HostInventoryEnvelope{
		Version: ProtocolVersion, Type: HostInventoryType, Profile: identityProfile(state.PublicIdentityRef),
		SessionID: state.SessionID, DeviceID: state.DeviceID,
		Inventory: inventory, InventoryHash: inventoryHash, Sequence: sequence,
	}
	var signErr error
	report.Signature, signErr = encodeIdentitySignature(identity, HostInventoryCanonical(report))
	if signErr != nil {
		return fmt.Errorf("sign host inventory: %w", signErr)
	}
	if err := writeSessionMessage(connection, report, writeTimeout); err != nil {
		return err
	}
	var accepted inventoryAcceptedMessage
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "host.inventory.accepted" || accepted.SessionID != report.SessionID || accepted.DeviceID != report.DeviceID || accepted.InventoryHash != report.InventoryHash || accepted.Sequence != report.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("host inventory was not accepted")
	}
	markInventoryAccepted(state)
	return SaveStateAtomic(client.StateDir, *state)
}

func (client Client) handleOperationCommand(
	ctx context.Context,
	state *State,
	identity Identity,
	connection *websocket.Conn,
	command operations.Command,
	coordinator *operations.Coordinator,
	writeTimeout time.Duration,
) error {
	current, phase, present, err := coordinator.CurrentCommand()
	if err != nil {
		return fmt.Errorf("operation state unavailable")
	}
	sameCommand := present && operations.SameCommand(current, command)
	if err := command.Validate(client.now()); err != nil {
		// Once the server has accepted an operation, its bounded expiry no
		// longer invalidates a reconnect replay.  The coordinator is the local
		// proof that this exact command was durably accepted before execution;
		// an unjournaled or different expired command still fails closed.
		if !sameCommand || (phase != operations.PhaseAccepted && phase != operations.PhaseExecutionStarted && phase != operations.PhaseExecuted) {
			return fmt.Errorf("operation command rejected")
		}
	}
	if present && current.CommandID == command.CommandID && !sameCommand {
		return fmt.Errorf("operation command conflict")
	}
	if present && current.CommandID != command.CommandID && phase != operations.PhaseResultAccepted {
		if phase == operations.PhaseExecuted {
			if err := client.replayOperationResult(ctx, state, identity, connection, coordinator, current, writeTimeout); err != nil {
				return err
			}
			phase = operations.PhaseResultAccepted
		} else {
			return fmt.Errorf("operation command is busy")
		}
	}
	var acceptance operations.CommandAcceptance
	if present && current.CommandID == command.CommandID && (phase == operations.PhaseAccepted || phase == operations.PhaseExecutionStarted || phase == operations.PhaseExecuted || phase == operations.PhaseResultAccepted) {
		// The coordinator already proves this exact command was accepted. Keep
		// reconnect replay independent of the delivery expiry; never ask the
		// new-command admission path to validate it as a fresh command.
		acceptance = operations.CommandAcceptance{Status: operations.AcceptanceDuplicate, Phase: phase, Command: current}
	} else {
		var err error
		acceptance, err = coordinator.Accept(command)
		if err != nil {
			return fmt.Errorf("operation command was not accepted")
		}
	}
	if err := client.sendOperationAck(ctx, state, identity, connection, command, acceptance.Status == operations.AcceptanceDuplicate, writeTimeout); err != nil {
		return err
	}
	if result, present, resultErr := coordinator.GetResult(); resultErr != nil {
		return fmt.Errorf("operation result unavailable")
	} else if present {
		if err := client.sendOperationResult(ctx, state, identity, connection, coordinator, command, result, writeTimeout); err != nil {
			return err
		}
		return nil
	}
	result, err := coordinator.ExecuteOnce(ctx)
	if err != nil {
		return fmt.Errorf("operation execution state unavailable")
	}
	return client.sendOperationResult(ctx, state, identity, connection, coordinator, command, result, writeTimeout)
}

func (client Client) replayOperationResult(
	ctx context.Context,
	state *State,
	identity Identity,
	connection *websocket.Conn,
	coordinator *operations.Coordinator,
	command operations.Command,
	writeTimeout time.Duration,
) error {
	result, present, err := coordinator.GetResult()
	if err != nil || !present {
		return fmt.Errorf("operation result unavailable")
	}
	return client.sendOperationResult(ctx, state, identity, connection, coordinator, command, result, writeTimeout)
}

func (client Client) sendOperationAck(
	ctx context.Context,
	state *State,
	identity Identity,
	connection *websocket.Conn,
	command operations.Command,
	duplicate bool,
	writeTimeout time.Duration,
) error {
	state.OperationSequence++
	if state.OperationSequence == 0 {
		return fmt.Errorf("operation sequence exhausted")
	}
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return fmt.Errorf("persist operation acknowledgement")
	}
	phase := "accepted"
	if duplicate {
		phase = "duplicate"
	}
	ack := OperationAckForCommand(command, state.SessionID, state.DeviceID, state.OperationSequence, client.now().UTC().Format(time.RFC3339Nano), phase)
	ack.Profile = identity.Profile()
	var err error
	ack.Signature, err = encodeIdentitySignature(identity, OperationAckCanonical(ack))
	if err != nil {
		return fmt.Errorf("sign operation acknowledgement: %w", err)
	}
	if err := writeSessionMessage(connection, ack, writeTimeout); err != nil {
		return err
	}
	var accepted operationAcceptedMessage
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != OperationAckAcceptedType || accepted.SessionID != ack.SessionID || accepted.DeviceID != ack.DeviceID || accepted.CommandID != ack.CommandID || accepted.CommandType != ack.CommandType || accepted.PayloadHash != ack.PayloadHash || accepted.Result != phase || accepted.Sequence != ack.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("operation acknowledgement was not accepted")
	}
	return nil
}

func (client Client) sendOperationResult(
	ctx context.Context,
	state *State,
	identity Identity,
	connection *websocket.Conn,
	coordinator *operations.Coordinator,
	command operations.Command,
	result operations.OperationResult,
	writeTimeout time.Duration,
) error {
	err := result.Validate()
	if err != nil || result.CommandType != command.CommandType {
		return fmt.Errorf("operation result is invalid")
	}
	state.OperationSequence++
	if state.OperationSequence == 0 {
		return fmt.Errorf("operation sequence exhausted")
	}
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return fmt.Errorf("persist operation result")
	}
	envelope := OperationResultForCommand(command, result, state.SessionID, state.DeviceID, state.OperationSequence)
	envelope.Profile = identity.Profile()
	envelope.Signature, err = encodeIdentitySignature(identity, OperationResultCanonical(envelope))
	if err != nil {
		return fmt.Errorf("sign operation result: %w", err)
	}
	if err := writeSessionMessage(connection, envelope, writeTimeout); err != nil {
		return err
	}
	var accepted operationAcceptedMessage
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != OperationResultAcceptedType || accepted.SessionID != envelope.SessionID || accepted.DeviceID != envelope.DeviceID || accepted.CommandID != envelope.CommandID || accepted.CommandType != envelope.CommandType || accepted.Result != string(envelope.Result) || accepted.Sequence != envelope.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("operation result was not accepted")
	}
	if err := coordinator.Acknowledge(command.CommandID); err != nil {
		return fmt.Errorf("persist operation acknowledgement")
	}
	return nil
}
