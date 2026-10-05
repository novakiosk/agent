package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/novakiosk/agent/cupsreconcile"
)

func verifyP256Test(ref string, canonical []byte, signature string) bool {
	if identityProfile(ref) != P256IdentityProfile {
		return false
	}
	key, err := decodeRaw(strings.TrimPrefix(ref, P256IdentityProfile+":"), 65)
	if err != nil {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), key)
	if x == nil {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(decoded) > 72 || encodeRaw(decoded) != signature {
		return false
	}
	hash := sha256.Sum256(canonical)
	return ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, hash[:], decoded)
}

func canonicalJSON[T any](fn func(T) []byte) func(json.RawMessage) []byte {
	return func(data json.RawMessage) []byte {
		var value T
		if json.Unmarshal(data, &value) != nil {
			return nil
		}
		return fn(value)
	}
}

func TestP256CrossLanguageWireFamilies(t *testing.T) {
	var fixture struct {
		PublicIdentityRef   string `json:"publicIdentityRef"`
		GoPublicIdentityRef string `json:"goPublicIdentityRef"`
		Vectors             []struct {
			Name          string          `json:"name"`
			Input         json.RawMessage `json:"input"`
			Canonical     string          `json:"canonical"`
			NodeSignature string          `json:"nodeSignature"`
			GoSignature   string          `json:"goSignature"`
		} `json:"vectors"`
	}
	data, err := os.ReadFile("../fixtures/identity-p256-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	constructors := map[string]func(json.RawMessage) []byte{
		"enrollmentCanonical": canonicalJSON(EnrollmentCanonical), "claimCanonical": canonicalJSON(ClaimCanonical), "challengeCanonical": canonicalJSON(ChallengeCanonical), "heartbeatCanonical": canonicalJSON(HeartbeatCanonical), "desiredAckCanonical": canonicalJSON(DesiredAckCanonical), "runtimeAckCanonical": canonicalJSON(RuntimeAckCanonical), "idleAckCanonical": canonicalJSON(IdleAckCanonical), "remoteDesktopAckCanonical": canonicalJSON(RemoteDesktopAckCanonical), "remoteDesktopPollCanonical": canonicalJSON(RemoteDesktopPollCanonical), "hostInventoryEnvelopeCanonical": canonicalJSON(HostInventoryCanonical), "operationAckCanonical": canonicalJSON(OperationAckCanonical), "operationResultCanonical": canonicalJSON(OperationResultCanonical), "printerReportEnvelopeCanonical": canonicalJSON(PrinterReportCanonical), "printerStatisticsEnvelopeCanonical": canonicalJSON(PrinterStatisticsCanonical), "printerJobsEnvelopeCanonical": canonicalJSON(PrinterJobsCanonical), "printerDesiredAckCanonical": canonicalJSON(cupsreconcile.AckCanonical), "printerDesiredAckCanonicalV2": canonicalJSON(cupsreconcile.AckCanonicalV2), "browserCommandCanonical": canonicalJSON(BrowserCommandCanonical), "browserCommandResultCanonical": canonicalJSON(BrowserCommandResultCanonical), "printerJobCommandCanonical": canonicalJSON(PrinterJobCommandCanonical), "printerJobCommandResultCanonical": canonicalJSON(PrinterJobCommandResultCanonical), "printerQueueCommandCanonical": canonicalJSON(PrinterQueueCommandCanonical), "printerQueueCommandResultCanonical": canonicalJSON(PrinterQueueCommandResultCanonical),
	}
	if len(fixture.Vectors) != len(constructors) {
		t.Fatalf("fixture has %d families, want %d", len(fixture.Vectors), len(constructors))
	}
	seen := make(map[string]bool, len(constructors))
	identity, err := CreateSoftwareIdentity(filepath.Join(t.TempDir(), "identity"), "opaque:device-01")
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			fn, ok := constructors[vector.Name]
			if !ok || seen[vector.Name] {
				t.Fatal("unknown or duplicate canonical family")
			}
			seen[vector.Name] = true
			canonical := fn(vector.Input)
			if string(canonical) != vector.Canonical {
				t.Fatalf("canonical mismatch:\n%s\nwant:\n%s", canonical, vector.Canonical)
			}
			if !verifyP256Test(fixture.PublicIdentityRef, canonical, vector.NodeSignature) {
				t.Fatal("Node signature rejected")
			}
			signature, err := encodeIdentitySignature(identity, canonical)
			if err != nil {
				t.Fatal(err)
			}
			if !verifyP256Test(identity.PublicIdentityRef, canonical, signature) {
				t.Fatal("Go signature rejected")
			}
			if !verifyP256Test(fixture.GoPublicIdentityRef, canonical, vector.GoSignature) {
				t.Fatal("recorded Go signature rejected")
			}
			if verifyP256Test(fixture.PublicIdentityRef, append(canonical, 'x'), vector.NodeSignature) {
				t.Fatal("changed message accepted")
			}
		})
	}

}

func TestP256PersistenceAndFailureControls(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	identity, err := CreateSoftwareIdentity(dir, "legacy:opaque-device")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadIdentity(dir)
	if err != nil || reloaded.DeviceID != identity.DeviceID || reloaded.PublicIdentityRef != identity.PublicIdentityRef {
		t.Fatalf("reload: %v", err)
	}
	canonical := HeartbeatCanonical(Heartbeat{Profile: P256IdentityProfile, DeviceID: identity.DeviceID, SessionID: "session", Sequence: 1})
	signature, err := encodeIdentitySignature(reloaded, canonical)
	if err != nil || !verifyP256Test(identity.PublicIdentityRef, canonical, signature) {
		t.Fatal("reloaded signer failed")
	}
	if _, err := CreateSoftwareIdentity(dir, identity.DeviceID); err == nil {
		t.Fatal("replaced existing identity")
	}
	original, _ := os.ReadFile(IdentityPath(dir))
	for name, mutate := range map[string]func(string){
		"missing": func(path string) {
			os.Remove(path)
			os.WriteFile(filepath.Join(filepath.Dir(path), "state.json"), []byte(`{}`), 0600)
		},
		"truncated": func(path string) { os.WriteFile(path, []byte("{"), 0600) },
		"public mismatch": func(path string) {
			os.WriteFile(path, bytes.Replace(original, []byte(identity.PublicIdentityRef), []byte("nova-p256-sha256-v1:AAAA"), 1), 0600)
		},
		"TPM fallback": func(path string) {
			os.WriteFile(path, bytes.Replace(original, []byte(SoftwareP256), []byte("tpm-p256"), 1), 0600)
		},
		"generation": func(path string) {
			os.WriteFile(path, bytes.Replace(original, []byte(`"generation":1`), []byte(`"generation":9007199254740992`), 1), 0600)
		},
		"readable": func(path string) { os.Chmod(path, 0640) },
		"symlink":  func(path string) { os.Remove(path); os.Symlink(IdentityPath(dir), path) },
	} {
		t.Run(name, func(t *testing.T) {
			broken := filepath.Join(t.TempDir(), "broken")
			os.Mkdir(broken, 0700)
			path := IdentityPath(broken)
			os.WriteFile(path, original, 0600)
			mutate(path)
			if _, err := LoadIdentity(broken); err == nil {
				t.Fatal("unsafe identity loaded")
			}
			if _, err := CreateSoftwareIdentity(broken, identity.DeviceID); err == nil {
				t.Fatal("failed state repaired")
			}
		})
	}
	t.Run("unsafe directory", func(t *testing.T) {
		os.Chmod(dir, 0750)
		defer os.Chmod(dir, 0700)
		if _, err := LoadIdentity(dir); err == nil {
			t.Fatal("unsafe directory accepted")
		}
	})
	t.Run("directory symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		os.Symlink(dir, link)
		if _, err := LoadIdentity(link); err == nil {
			t.Fatal("directory symlink accepted")
		}
	})
}

func TestP256WrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("foreign ownership fixture runs inside disposable container")
	}
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "identity")
			if _, err := CreateSoftwareIdentity(dir, "device-1"); err != nil {
				t.Fatal(err)
			}
			target := IdentityPath(dir)
			if directory {
				target = dir
			}
			if err := os.Chown(target, 12345, 12345); err != nil {
				t.Fatal(err)
			}
			defer os.Chown(target, 0, 0)
			if _, err := LoadIdentity(dir); err == nil {
				t.Fatal("foreign owner loaded")
			}
		})
	}
}

func TestMissingIdentityAndMismatchedEdSeedFailClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	identity, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	bytesBefore, _ := os.ReadFile(IdentityPath(dir))
	var persisted persistedIdentity
	if err := json.Unmarshal(bytesBefore, &persisted); err != nil {
		t.Fatal(err)
	}
	key, _ := base64.RawURLEncoding.DecodeString(persisted.PrivateKey)
	key[0] ^= 1
	persisted.PrivateKey = encodeRaw(key)
	broken, _ := json.Marshal(persisted)
	os.WriteFile(IdentityPath(dir), broken, 0600)
	if _, err := LoadIdentity(dir); err == nil {
		t.Fatal("inconsistent seed/public suffix accepted")
	}
	os.Remove(IdentityPath(dir))
	if _, err := LoadOrCreateIdentity(dir); err == nil {
		t.Fatal("missing identity silently regenerated")
	}
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{}`), 0600)
	if _, err := CreateSoftwareIdentity(dir, identity.DeviceID); err == nil {
		t.Fatal("existing authority state replaced")
	}
}

func TestBrowserCommandRejectsOtherIdentityProfile(t *testing.T) {
	identity, err := CreateSoftwareIdentity(filepath.Join(t.TempDir(), "identity"), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	command := BrowserCommand{Version: 1, Type: BrowserCommandType, Profile: ProvisionalIdentityProfile, CommandID: "00000000-0000-4000-8000-000000000001", Action: "reload", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	command.PayloadHash = BrowserCommandHash(command)
	client := Client{Now: func() time.Time { return now }}
	err = client.applyBrowserCommand(context.Background(), &State{}, identity, nil, nil, nil, "", DesiredSnapshot{BrowserCommand: &command}, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "profile mismatch") {
		t.Fatalf("wrong-profile command: %v", err)
	}
}

func TestConcurrentP256FirstCreationDoesNotReplaceWinner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	const count = 16
	start := make(chan struct{})
	results := make(chan Identity, count)
	var wait sync.WaitGroup
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			identity, err := CreateSoftwareIdentity(dir, "device-1")
			if err == nil {
				results <- identity
			}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var successful []Identity
	for identity := range results {
		successful = append(successful, identity)
	}
	if len(successful) != 1 {
		t.Fatalf("successful creations: %d", len(successful))
	}
	loaded, err := LoadIdentity(dir)
	if err != nil || loaded.PublicIdentityRef != successful[0].PublicIdentityRef {
		t.Fatalf("winning identity replaced: %v", err)
	}
}
