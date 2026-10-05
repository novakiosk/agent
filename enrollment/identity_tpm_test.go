package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/novakiosk/agent/tpmsigner"
	"os"
	"path/filepath"
	"testing"
)

func TestTPMMetadataInspectionNeverOpensHardwareOrRepairs(t *testing.T) {
	// This fixture has valid public metadata but deliberately synthetic wrapped
	// private data. It can be inspected even without a TPM; it is not a usable key.
	data, err := os.ReadFile("../fixtures/tpm-metadata-only-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var bundle tpmsigner.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	public, err := tpmsigner.ValidateBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := signerPublicRef(publicOnlySigner{public})
	if err != nil {
		t.Fatal(err)
	}
	record := persistedIdentity{Version: 1, Profile: P256IdentityProfile, PublicIdentityRef: ref, DeviceID: "opaque-device", Backing: TPMP256, Generation: 2, TPM: &bundle}
	encoded, _ := json.Marshal(record)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if err := os.WriteFile(IdentityPath(dir), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := InspectIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Backing != TPMP256 || metadata.Generation != 2 || metadata.PublicIdentityRef != ref {
		t.Fatal("metadata mismatch")
	}
	if _, err := metadata.sign([]byte("canonical")); !errors.Is(err, ErrIdentity) {
		t.Fatal("inspection granted signing authority")
	}
	if _, err := LoadIdentityForReset(dir); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(IdentityPath(dir))
	if !bytes.Equal(encoded, after) {
		t.Fatal("inspection rewrote bundle")
	}
	if _, err := os.Stat("/dev/tpmrm0"); errors.Is(err, os.ErrNotExist) {
		if identity, err := LoadIdentity(dir); err == nil {
			identity.Close()
			t.Fatal("TPM identity silently fell back")
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != filepath.Base(IdentityPath(dir)) {
		t.Fatal("inspection generated replacement state")
	}
}
