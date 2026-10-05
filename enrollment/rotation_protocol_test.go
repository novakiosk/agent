package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRotationSharedCanonicalDualProofs(t *testing.T) {
	var fixture struct {
		Transcript   RotationTranscript `json:"transcript"`
		Canonical    string             `json:"canonicalBase64"`
		OldSignature string             `json:"oldSignature"`
		NewSignature string             `json:"newSignature"`
	}
	data, err := os.ReadFile("../fixtures/identity-rotation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	expected, err := base64.StdEncoding.DecodeString(fixture.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonical := RotationCanonical(fixture.Transcript)
	if !bytes.Equal(canonical, expected) {
		t.Fatal("Go/TS rotation canonical mismatch")
	}
	old, _ := decodeRaw(strings.TrimPrefix(fixture.Transcript.OldPublicIdentityRef, ProvisionalIdentityProfile+":"), 32)
	signature, _ := decodeRaw(fixture.OldSignature, 64)
	if !ed25519.Verify(old, canonical, signature) || !verifyP256Test(fixture.Transcript.NewPublicIdentityRef, canonical, fixture.NewSignature) {
		t.Fatal("cross-language dual proof invalid")
	}
	changed := fixture.Transcript
	changed.NewGeneration++
	if ed25519.Verify(old, RotationCanonical(changed), signature) || verifyP256Test(changed.NewPublicIdentityRef, RotationCanonical(changed), fixture.NewSignature) {
		t.Fatal("generation substitution accepted")
	}
}
