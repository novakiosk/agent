package enrollment

import (
	"errors"
	"fmt"

	"github.com/novakiosk/agent/operations"
)

var ErrPendingInventoryCorrupt = errors.New("pending host inventory state is invalid")

// prepareInventoryReport keeps the latest semantic snapshot and leaves it
// pending until the control plane explicitly accepts the signed report.
// Pending snapshots are replayed verbatim across reconnects; a newly observed
// change is not allowed to overwrite an unacknowledged report.
func prepareInventoryReport(state *State, collector *operations.InventoryCollector) (operations.Inventory, string, uint64, bool, error) {
	if state == nil || collector == nil {
		return operations.Inventory{}, "", 0, false, fmt.Errorf("host inventory is unavailable")
	}
	if state.InventoryPending && state.LastInventory == nil {
		return operations.Inventory{}, "", 0, false, ErrPendingInventoryCorrupt
	}
	if state.InventoryPending && state.LastInventory != nil {
		hash, err := InventoryHash(*state.LastInventory)
		if err != nil {
			return operations.Inventory{}, "", 0, false, ErrPendingInventoryCorrupt
		}
		if state.InventorySequence == 0 || state.LastInventoryHash != hash {
			return operations.Inventory{}, "", 0, false, ErrPendingInventoryCorrupt
		}
		return *state.LastInventory, hash, state.InventorySequence, true, nil
	}
	inventory, err := collector.Collect()
	if err != nil {
		return operations.Inventory{}, "", 0, false, err
	}
	hash, err := InventoryHash(inventory)
	if err != nil {
		return operations.Inventory{}, "", 0, false, err
	}
	if state.LastInventory != nil && state.LastInventoryHash == hash {
		return inventory, hash, state.InventorySequence, false, nil
	}
	state.InventorySequence++
	if state.InventorySequence == 0 {
		return operations.Inventory{}, "", 0, false, fmt.Errorf("host inventory sequence exhausted")
	}
	state.LastInventory = &inventory
	state.LastInventoryHash = hash
	state.InventoryPending = true
	return inventory, hash, state.InventorySequence, true, nil
}

func markInventoryAccepted(state *State) {
	if state != nil {
		state.InventoryPending = false
	}
}
