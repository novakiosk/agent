package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/novakiosk/agent/operations"
)

const (
	HostInventoryProfile        = ProvisionalIdentityProfile
	HostInventoryType           = "host.inventory"
	OperationAckType            = "operation.ack"
	OperationResultType         = "operation.result"
	OperationAckAcceptedType    = "operation.ack.accepted"
	OperationResultAcceptedType = "operation.result.accepted"
)

// HostInventoryEnvelope is the signed managed-session evidence for one
// bounded physical host inventory snapshot. The nested inventory is kept
// separate from its hash so the server can validate both representations.
type HostInventoryEnvelope struct {
	Version       int                  `json:"version"`
	Type          string               `json:"type"`
	Profile       string               `json:"profile"`
	SessionID     string               `json:"sessionId"`
	DeviceID      string               `json:"deviceId"`
	Inventory     operations.Inventory `json:"inventory"`
	InventoryHash string               `json:"inventoryHash"`
	Sequence      uint64               `json:"sequence"`
	Signature     string               `json:"signature"`
}

type OperationAck struct {
	Version     int                    `json:"version"`
	Type        string                 `json:"type"`
	Profile     string                 `json:"profile"`
	SessionID   string                 `json:"sessionId"`
	DeviceID    string                 `json:"deviceId"`
	CommandID   string                 `json:"commandId"`
	CommandType operations.CommandType `json:"commandType"`
	PayloadHash string                 `json:"payloadHash"`
	Phase       string                 `json:"phase"`
	ObservedAt  string                 `json:"observedAt"`
	Sequence    uint64                 `json:"sequence"`
	Signature   string                 `json:"signature"`
}

type OperationResultEnvelope struct {
	Version       int                             `json:"version"`
	Type          string                          `json:"type"`
	Profile       string                          `json:"profile"`
	SessionID     string                          `json:"sessionId"`
	DeviceID      string                          `json:"deviceId"`
	CommandID     string                          `json:"commandId"`
	CommandType   operations.CommandType          `json:"commandType"`
	Result        operations.OperationResultState `json:"result"`
	ErrorCategory *operations.ErrorCategory       `json:"errorCategory"`
	ObservedAt    string                          `json:"observedAt"`
	BootIDBefore  string                          `json:"bootIdBefore"`
	Sequence      uint64                          `json:"sequence"`
	Signature     string                          `json:"signature"`
}

func InventoryHash(inventory operations.Inventory) (string, error) {
	payload, err := inventory.CanonicalPayload()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func HostInventoryCanonical(report HostInventoryEnvelope) []byte {
	return CanonicalV1(HostInventoryType,
		CanonicalField{"version", "1"},
		CanonicalField{"profile", HostInventoryProfile},
		CanonicalField{"sessionId", report.SessionID},
		CanonicalField{"deviceId", report.DeviceID},
		CanonicalField{"inventoryHash", report.InventoryHash},
		CanonicalField{"sequence", fmt.Sprintf("%d", report.Sequence)},
	)
}

func OperationAckCanonical(ack OperationAck) []byte {
	return CanonicalV1(OperationAckType,
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", ack.SessionID},
		CanonicalField{"deviceId", ack.DeviceID},
		CanonicalField{"commandId", ack.CommandID},
		CanonicalField{"commandType", string(ack.CommandType)},
		CanonicalField{"payloadHash", ack.PayloadHash},
		CanonicalField{"phase", ack.Phase},
		CanonicalField{"observedAt", ack.ObservedAt},
		CanonicalField{"sequence", fmt.Sprintf("%d", ack.Sequence)},
	)
}

func OperationResultCanonical(result OperationResultEnvelope) []byte {
	errorCategory := ""
	if result.ErrorCategory != nil {
		errorCategory = string(*result.ErrorCategory)
	}
	return CanonicalV1(OperationResultType,
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", result.SessionID},
		CanonicalField{"deviceId", result.DeviceID},
		CanonicalField{"commandId", result.CommandID},
		CanonicalField{"commandType", string(result.CommandType)},
		CanonicalField{"result", string(result.Result)},
		CanonicalField{"errorCategory", errorCategory},
		CanonicalField{"observedAt", result.ObservedAt},
		CanonicalField{"bootIdBefore", result.BootIDBefore},
		CanonicalField{"sequence", fmt.Sprintf("%d", result.Sequence)},
	)
}

func OperationAckForCommand(command operations.Command, sessionID, deviceID string, sequence uint64, observedAt string, phase string) OperationAck {
	return OperationAck{Version: ProtocolVersion, Type: OperationAckType, Profile: ProvisionalIdentityProfile, SessionID: sessionID, DeviceID: deviceID, CommandID: command.CommandID, CommandType: command.CommandType, PayloadHash: command.PayloadHash, Phase: phase, ObservedAt: observedAt, Sequence: sequence}
}

func OperationResultForCommand(command operations.Command, result operations.OperationResult, sessionID, deviceID string, sequence uint64) OperationResultEnvelope {
	return OperationResultEnvelope{Version: ProtocolVersion, Type: OperationResultType, Profile: ProvisionalIdentityProfile, SessionID: sessionID, DeviceID: deviceID, CommandID: command.CommandID, CommandType: command.CommandType, Result: result.Result, ErrorCategory: result.ErrorCategory, ObservedAt: result.ObservedAt, BootIDBefore: result.BootIDBefore, Sequence: sequence}
}
