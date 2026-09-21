package enrollment

import (
	"testing"
	"time"

	"github.com/novakiosk/agent/operations"
)

func TestPendingInventoryHashCorruptionFailsClosed(t *testing.T) {
	inventory := operations.Inventory{
		Version: operations.InventoryVersion,
		Type:    operations.InventoryType,
		BootID:  "01234567-89ab-cdef-0123-456789abcdef",
	}
	state := State{InventoryPending: true, InventorySequence: 1, LastInventoryHash: "not-the-hash", LastInventory: &inventory}
	_, _, _, _, err := prepareInventoryReport(&state, operations.NewInventoryCollector(operations.InventoryConfig{FS: nil}))
	if err != ErrPendingInventoryCorrupt {
		t.Fatalf("pending corruption error = %v", err)
	}
}

func TestDesiredSnapshotReplayAllowsLateAcceptedOperation(t *testing.T) {
	now := time.Now().UTC()
	command := operations.Command{
		Version: operations.CommandVersion, Type: operations.CommandMessageType,
		CommandID: "01234567-89ab-cdef-0123-456789abcdef", CommandType: operations.CommandSystemUpdate,
		IssuedAt: now.Add(-30 * time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
	}
	var err error
	command.PayloadHash, err = command.CanonicalPayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := DesiredSnapshot{Version: ProtocolVersion, Type: "desired.snapshot", SessionID: "session-1", DeviceID: "device-1", Operation: &command}
	if err := validateDesiredSnapshot(snapshot, snapshot.SessionID, snapshot.DeviceID); err == nil {
		t.Fatal("expired command unexpectedly passed fresh validation")
	}
	if err := validateDesiredSnapshotWithReplay(snapshot, snapshot.SessionID, snapshot.DeviceID, true); err != nil {
		t.Fatalf("accepted command replay rejected: %v", err)
	}
}
