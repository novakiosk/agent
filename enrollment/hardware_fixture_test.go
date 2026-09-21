package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/novakiosk/agent/operations"
)

type hardwareFixture struct {
	Inventory     operations.Inventory    `json:"inventory"`
	InventoryHash string                  `json:"inventoryHash"`
	Command       operations.Command      `json:"command"`
	Ack           OperationAck            `json:"ack"`
	AckHash       string                  `json:"ackHash"`
	Result        OperationResultEnvelope `json:"result"`
	ResultHash    string                  `json:"resultHash"`
}

func fixtureDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestHardwareEvidenceMatchesTypeScriptFixture(t *testing.T) {
	payload, err := os.ReadFile("../fixtures/hardware-operations-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture hardwareFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Inventory.Validate(); err != nil {
		t.Fatal(err)
	}
	inventoryHash, err := InventoryHash(fixture.Inventory)
	if err != nil || inventoryHash != fixture.InventoryHash {
		t.Fatalf("inventory hash = %q, want %q (err=%v)", inventoryHash, fixture.InventoryHash, err)
	}
	if err := fixture.Command.Validate(time.Date(2026, 8, 25, 12, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	ackHash := fixtureDigest(OperationAckCanonical(fixture.Ack))
	if ackHash != fixture.AckHash {
		t.Fatalf("ack hash = %q, want %q", ackHash, fixture.AckHash)
	}
	resultHash := fixtureDigest(OperationResultCanonical(fixture.Result))
	if resultHash != fixture.ResultHash {
		t.Fatalf("result hash = %q, want %q", resultHash, fixture.ResultHash)
	}
}

func TestHardwareInventoryASCIIOrderingMatchesTypeScript(t *testing.T) {
	inventory := operations.Inventory{
		Version: operations.InventoryVersion, Type: operations.InventoryType,
		BootID: "01234567-89ab-cdef-0123-456789abcdef",
		Interfaces: []operations.InterfaceObservation{
			{Name: "z0", MAC: "02:11:22:33:44:55", OperState: operations.OperStateUp},
			{Name: "A0", MAC: "a2:bb:cc:dd:ee:ff", OperState: operations.OperStateDown},
			{Name: "a0", MAC: "04:bb:cc:dd:ee:ff", OperState: operations.OperStateUnknown},
		},
	}
	hash, err := InventoryHash(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "d86b53b99044647b315940f0ae9696e2b90b8da2de43c7ee79d48f204645f122" {
		t.Fatalf("inventory hash = %q", hash)
	}
}
