package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testOptions(instance string) EnrollOptions {
	return EnrollOptions{
		InstanceURL:       instance,
		DeviceID:          "device-test-01",
		PublicIdentityRef: "identity-test-01",
		ProofKind:         "fixture",
		ProofValue:        "fixture-proof-01",
		Inventory: Inventory{
			Hostname:     "test-kiosk",
			OSVersion:    "nova-os-test",
			AgentVersion: "0.1.0",
			Capabilities: []string{"display"},
		},
		RequestedScope: "site:test",
		IdempotencyKey: "enrollment-test-key",
	}
}

func tempStateDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "agent-state")
}

type testTLSServer struct {
	URL      string
	listener net.Listener
	server   *http.Server
}

func (server *testTLSServer) Close() {
	_ = server.server.Close()
	_ = server.listener.Close()
}

func trustedTLSServer(t *testing.T, handler http.Handler) (*testTLSServer, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "novakiosk-agent-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyPair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: certificate}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{keyPair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("trusted TLS integration requires a network socket: %v", err)
		}
		t.Fatal(err)
	}
	server := &testTLSServer{
		URL:      "https://" + listener.Addr().String(),
		listener: listener,
		server:   &http.Server{Handler: handler},
	}
	go func() { _ = server.server.Serve(listener) }()
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "test-ca.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return server, caFile
}

func validResultBody(deviceID, expiresAt string) string {
	return fmt.Sprintf(`{"version":1,"type":"bootstrap.enrollment.result","status":"pending","enrollmentId":"enrollment-test-01","deviceId":%q,"comparisonValue":"compare-test-01","expiresAt":%q}`,
		deviceID,
		expiresAt,
	)
}

type scriptedDoer func(*http.Request) (*http.Response, error)

func (doer scriptedDoer) Do(request *http.Request) (*http.Response, error) {
	return doer(request)
}

func responseFor(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d test", status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func requestFromHTTP(request *http.Request) Request {
	var payload Request
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		panic(err)
	}
	return payload
}

func TestStatusIsUnconfiguredWithoutState(t *testing.T) {
	state, _, err := Status(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if state != "Unconfigured" {
		t.Fatalf("status = %q, want Unconfigured", state)
	}
}

func TestEnrollmentCodePromptNormalizesSeparatorsAndCase(t *testing.T) {
	code, err := NormalizeEnrollmentCode("  BABA__BeBe-bIbI  ")
	if err != nil {
		t.Fatal(err)
	}
	if code != "baba-bebe-bibi" {
		t.Fatalf("normalized code = %q", code)
	}
	var output bytes.Buffer
	code, err = ReadEnrollmentCode(strings.NewReader("BABA bebe bibi\n"), &output)
	if err != nil || code != "baba-bebe-bibi" {
		t.Fatalf("prompt result = %q, %v", code, err)
	}
	if output.String() != "Enrollment code: " {
		t.Fatalf("prompt output = %q", output.String())
	}
}

func TestEnrollmentCodePromptRejectsEmptyOrEOF(t *testing.T) {
	for _, input := range []string{"\n", ""} {
		if _, err := ReadEnrollmentCode(strings.NewReader(input), io.Discard); err == nil {
			t.Fatalf("input %q was accepted", input)
		}
	}
}

func TestEnrollmentCodeHeaderIsNotPersisted(t *testing.T) {
	stateDir := tempStateDir(t)
	options := testOptions("https://control.example")
	options.RequestedScope = "site:hardware"
	options.EnrollmentCode = "BABA__BeBe-bIbI"
	var captured *http.Request
	client := Client{StateDir: stateDir, Now: func() time.Time { return time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC) }}
	client.doer = scriptedDoer(func(request *http.Request) (*http.Response, error) {
		captured = request
		return responseFor(request, http.StatusCreated, validResultBody(options.DeviceID, "2026-08-24T10:10:00Z")), nil
	})
	if _, err := client.Enroll(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if captured == nil || captured.Header.Get("Nova-Enrollment-Code") != "baba-bebe-bibi" {
		t.Fatalf("enrollment code header was not sent")
	}
	if got := requestFromHTTP(captured).RequestedScope; got != "site:hardware" {
		t.Fatalf("requested scope = %q, want site:hardware", got)
	}
	for _, path := range []string{IdentityPath(stateDir), StatePath(stateDir), filepath.Join(stateDir, "pending-attempt.json")} {
		data, err := os.ReadFile(path)
		if err == nil && (strings.Contains(string(data), options.EnrollmentCode) || strings.Contains(string(data), captured.Header.Get("Nova-Enrollment-Code"))) {
			t.Fatalf("enrollment code leaked into %s", path)
		}
	}
}

func TestProvisionalIdentityIsDurablePrivateAndReused(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "identity-state")
	first, err := LoadOrCreateIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicIdentityRef != second.PublicIdentityRef || string(first.signer.(ed25519.PrivateKey)) != string(second.signer.(ed25519.PrivateKey)) || first.DeviceID != second.DeviceID {
		t.Fatal("identity was not reused")
	}
	if matched, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, first.DeviceID); !matched {
		t.Fatalf("generated device ID = %q, want UUID-shaped opaque ID", first.DeviceID)
	}
	directoryInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("identity directory mode = %o, want 700", got)
	}
	identityInfo, err := os.Stat(IdentityPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if got := identityInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity file mode = %o, want 600", got)
	}
	if matches, _ := filepath.Glob(filepath.Join(stateDir, ".identity-*.tmp")); len(matches) != 0 {
		t.Fatalf("identity temporary artifacts remain: %v", matches)
	}
}

func TestResetClearsAuthorityFilesAndPreservesIdentityBytes(t *testing.T) {
	stateDir := tempStateDir(t)
	identity, err := LoadOrCreateIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	identityBefore, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveStateAtomic(stateDir, State{
		Version: 1, Status: "Pending", InstanceURL: "https://control.example",
		EnrollmentID: "enrollment-01", DeviceID: identity.DeviceID,
		PublicIdentityRef: identity.PublicIdentityRef,
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveAttemptAtomic(stateDir, Request{
		Version: 1, Type: "bootstrap.enrollment", IdempotencyKey: "attempt-01",
		DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef,
		Proof: Proof{Kind: "fixture", Value: "opaque-proof"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Reset(stateDir); err != nil {
		t.Fatal(err)
	}
	identityAfter, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil || !bytes.Equal(identityBefore, identityAfter) {
		t.Fatalf("identity changed after reset: read error=%v", err)
	}
	if _, err := os.Stat(StatePath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state remains after reset: %v", err)
	}
	if _, err := os.Stat(attemptPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending attempt remains after reset: %v", err)
	}
	loaded, err := LoadIdentity(stateDir)
	if err != nil || loaded.DeviceID != identity.DeviceID || !bytes.Equal(loaded.signer.(ed25519.PrivateKey), identity.signer.(ed25519.PrivateKey)) {
		t.Fatalf("identity did not survive reset: %+v, %v", loaded, err)
	}
	if err := Reset(stateDir); err != nil {
		t.Fatalf("absent state and attempt should be harmless: %v", err)
	}
}

func TestResetRejectsBlankAndUnsafeArtifacts(t *testing.T) {
	if err := Reset("   "); err == nil {
		t.Fatal("blank state directory was accepted")
	}
	stateDir := tempStateDir(t)
	if _, err := LoadOrCreateIdentity(stateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StatePath(stateDir), []byte("unsafe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Reset(stateDir); err == nil {
		t.Fatal("unsafe state permissions were accepted")
	}
	if err := os.Remove(StatePath(stateDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(IdentityPath(stateDir), StatePath(stateDir)); err != nil {
		t.Fatal(err)
	}
	if err := Reset(stateDir); err == nil {
		t.Fatal("symlink state artifact was accepted")
	}
}

func writeLegacyIdentity(t *testing.T, stateDir string, identity Identity) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(persistedIdentity{
		Version: ProtocolVersion, Profile: ProvisionalIdentityProfile,
		PublicIdentityRef: identity.PublicIdentityRef, PrivateKey: encodeRaw(identity.signer.(ed25519.PrivateKey)),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(IdentityPath(stateDir), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyIdentityMigrationPreservesStateDeviceIDAndPrivateKey(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyIdentity(t, stateDir, legacy)
	if err := SaveStateAtomic(stateDir, State{Version: 1, Status: "Pending", InstanceURL: "https://control.example", EnrollmentID: "enrollment-01", DeviceID: "state-device-01", PublicIdentityRef: legacy.PublicIdentityRef}); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateLegacyIdentity(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if migrated.DeviceID != "state-device-01" || string(migrated.signer.(ed25519.PrivateKey)) != string(legacy.signer.(ed25519.PrivateKey)) || migrated.PublicIdentityRef != legacy.PublicIdentityRef {
		t.Fatalf("migrated identity = %+v, key changed or state device ID was not preserved", migrated)
	}
	persisted, err := LoadIdentity(stateDir)
	if err != nil || persisted.DeviceID != migrated.DeviceID {
		t.Fatalf("persisted migration = %+v, %v", persisted, err)
	}
	data, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil || !strings.Contains(string(data), `"deviceId": "state-device-01"`) {
		t.Fatalf("migrated identity file does not contain device ID: %v", err)
	}
}

func TestLegacyIdentityMigrationPreservesPendingAttemptDeviceID(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyIdentity(t, stateDir, legacy)
	if err := SaveAttemptAtomic(stateDir, Request{Version: 1, Type: "bootstrap.enrollment", IdempotencyKey: "pending-key", DeviceID: "pending-device-01", PublicIdentityRef: legacy.PublicIdentityRef, Proof: Proof{Kind: ProvisionalIdentityProfile, Value: "opaque-proof"}}); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateLegacyIdentity(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if migrated.DeviceID != "pending-device-01" || string(migrated.signer.(ed25519.PrivateKey)) != string(legacy.signer.(ed25519.PrivateKey)) {
		t.Fatalf("pending attempt migration = %+v", migrated)
	}
}

func TestLegacyIdentityMigrationRequiresAuthorityFiles(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, _ := GenerateIdentity()
	writeLegacyIdentity(t, stateDir, legacy)
	before, _ := os.ReadFile(IdentityPath(stateDir))
	if _, err := LoadIdentity(stateDir); err == nil {
		t.Fatal("load migrated missing device ID")
	}
	if _, err := MigrateLegacyIdentity(stateDir, ""); err == nil {
		t.Fatal("migration generated a device ID")
	}
	after, _ := os.ReadFile(IdentityPath(stateDir))
	if !bytes.Equal(before, after) {
		t.Fatal("failed migration mutated identity")
	}
}

func TestLegacyIdentityMigrationRefusesInvalidExistingState(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyIdentity(t, stateDir, legacy)
	if err := os.WriteFile(StatePath(stateDir), []byte(`{"not":"state"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyIdentity(stateDir, ""); err == nil {
		t.Fatal("legacy identity migration accepted malformed existing state")
	}
	data, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil || strings.Contains(string(data), "deviceId") {
		t.Fatalf("identity was rewritten after invalid state: %v", err)
	}
}

func TestLegacyIdentityMigrationRefusesUnsafePendingAttempt(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyIdentity(t, stateDir, legacy)
	if err := SaveAttemptAtomic(stateDir, Request{Version: 1, Type: "bootstrap.enrollment", IdempotencyKey: "pending-key", DeviceID: "pending-device-01", PublicIdentityRef: legacy.PublicIdentityRef, Proof: Proof{Kind: ProvisionalIdentityProfile, Value: "opaque-proof"}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(attemptPath(stateDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyIdentity(stateDir, ""); err == nil {
		t.Fatal("legacy identity migration accepted unsafe existing pending attempt")
	}
}

func TestLegacyIdentityMigrationRefusesMismatchedStateIdentityWithoutRewrite(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyIdentity(t, stateDir, legacy)
	original, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveStateAtomic(stateDir, State{Version: 1, Status: "Pending", InstanceURL: "https://control.example", EnrollmentID: "enrollment-01", DeviceID: "state-device-01", PublicIdentityRef: "provisional-ed25519-v1:other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyIdentity(stateDir, ""); err == nil || !strings.Contains(err.Error(), "does not match local identity") {
		t.Fatalf("error = %v, want state identity mismatch", err)
	}
	current, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil || !bytes.Equal(current, original) {
		t.Fatalf("identity changed after state identity mismatch: read error=%v", err)
	}
}

func TestLegacyIdentityMigrationRefusesMismatchedAttemptIdentityWithoutRewrite(t *testing.T) {
	stateDir := tempStateDir(t)
	legacy, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyIdentity(t, stateDir, legacy)
	original, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAttemptAtomic(stateDir, Request{Version: 1, Type: "bootstrap.enrollment", IdempotencyKey: "pending-key", DeviceID: "pending-device-01", PublicIdentityRef: "provisional-ed25519-v1:other", Proof: Proof{Kind: ProvisionalIdentityProfile, Value: "opaque-proof"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyIdentity(stateDir, ""); err == nil || !strings.Contains(err.Error(), "does not match local identity") {
		t.Fatalf("error = %v, want pending identity mismatch", err)
	}
	current, err := os.ReadFile(IdentityPath(stateDir))
	if err != nil || !bytes.Equal(current, original) {
		t.Fatalf("identity changed after pending identity mismatch: read error=%v", err)
	}
}

func TestLoadRejectsUnsafeIdentityAndStateFiles(t *testing.T) {
	identityDir := filepath.Join(t.TempDir(), "identity-state")
	identity, err := LoadOrCreateIdentity(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(IdentityPath(identityDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(identityDir); err == nil {
		t.Fatal("group/world-readable identity was accepted")
	}
	if err := os.Chmod(IdentityPath(identityDir), 0o600); err != nil {
		t.Fatal(err)
	}

	stateDir := tempStateDir(t)
	if err := SaveStateAtomic(stateDir, State{
		Version: 1, Status: "Pending", InstanceURL: "https://control.example", EnrollmentID: "enrollment-01", DeviceID: "device-01", PublicIdentityRef: identity.PublicIdentityRef,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(StatePath(stateDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(stateDir); err == nil {
		t.Fatal("group/world-readable state was accepted")
	}
}

func TestLoadStateCanonicalizesEquivalentInstanceOrigin(t *testing.T) {
	stateDir := tempStateDir(t)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Write an existing state's raw bytes so SaveStateAtomic cannot normalize
	// the origin before LoadState gets a chance to exercise its own validation.
	data := []byte(`{"version":1,"status":"Pending","instanceUrl":"https://CONTROL.example:443/","enrollmentId":"enrollment-01","deviceId":"device-01"}`)
	if err := os.WriteFile(StatePath(stateDir), data, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.InstanceURL != "https://control.example" {
		t.Fatalf("loaded instance origin = %q", state.InstanceURL)
	}
}

func TestClaimResponseRejectsUnknownFields(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Status: "Pending", InstanceURL: "https://control.example", EnrollmentID: "enrollment-01", DeviceID: "device-01"}
	client := Client{StateDir: t.TempDir(), doer: scriptedDoer(func(request *http.Request) (*http.Response, error) {
		return responseFor(request, http.StatusOK, `{"version":1,"type":"bootstrap.identity.claim.result","status":"pending","enrollmentId":"enrollment-01","deviceId":"device-01","identityState":"unbound","identityBindingId":null,"sessionPath":null,"authority":"managed"}`), nil
	})}
	if _, err := client.Claim(context.Background(), state, identity); err == nil {
		t.Fatal("claim decoder accepted an unknown authority field")
	}
}

func TestEnrollRejectsDeviceIDThatDoesNotMatchLocalIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	options := testOptions("https://control.example")
	options.DeviceID = "different-device-01"
	options.Identity = &identity
	_, err = (Client{StateDir: tempStateDir(t)}).Enroll(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "does not match local identity") {
		t.Fatalf("error = %v, want local identity device mismatch", err)
	}
}

func TestCanonicalIdentityFixtureVerifies(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "identity-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicIdentityRef  string `json:"publicIdentityRef"`
		Canonical          string `json:"canonicalEnrollment"`
		Signature          string `json:"enrollmentSignature"`
		CanonicalClaim     string `json:"canonicalClaim"`
		ClaimSignature     string `json:"claimSignature"`
		CanonicalChallenge string `json:"canonicalChallenge"`
		ChallengeSignature string `json:"challengeSignature"`
		CanonicalHeartbeat string `json:"canonicalHeartbeat"`
		HeartbeatSignature string `json:"heartbeatSignature"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	request := Request{
		Version: 1, Type: "bootstrap.enrollment", DeviceID: "fixture-device", PublicIdentityRef: fixture.PublicIdentityRef,
		Inventory:      Inventory{Hostname: "fixture-host", OSVersion: "nova-os", AgentVersion: "0.3.0", Capabilities: []string{"display", "heartbeat"}},
		RequestedScope: "site:fixture", IdempotencyKey: "fixture-idempotency", Nonce: "fixture-nonce", Audience: "https://control.example", ExpiresAt: "2099-01-01T00:00:00Z",
	}
	if string(EnrollmentCanonical(request)) != fixture.Canonical {
		t.Fatal("cross-language canonical enrollment fixture did not match")
	}
	if !VerifySignature(fixture.PublicIdentityRef, EnrollmentCanonical(request), fixture.Signature) {
		t.Fatal("cross-language identity fixture signature did not verify")
	}
	claim := IdentityClaim{Version: 1, Type: "bootstrap.identity.claim", EnrollmentID: "fixture-enrollment", DeviceID: "fixture-device", PublicIdentityRef: fixture.PublicIdentityRef, Nonce: "fixture-claim-nonce", Audience: "https://control.example", ExpiresAt: "2099-01-01T00:05:00Z"}
	if string(ClaimCanonical(claim)) != fixture.CanonicalClaim || !VerifySignature(fixture.PublicIdentityRef, ClaimCanonical(claim), fixture.ClaimSignature) {
		t.Fatal("cross-language identity fixture claim did not match")
	}
	challenge := ChallengeResponse{Version: 1, Type: "session.challenge.response", Profile: ProvisionalIdentityProfile, SessionID: "fixture-session", ChallengeID: "fixture-challenge", EnrollmentID: "fixture-enrollment", IdentityBindingID: "fixture-binding", DeviceID: "fixture-device", PublicIdentityRef: fixture.PublicIdentityRef, Nonce: "fixture-challenge-nonce", Audience: "https://control.example", ExpiresAt: "2099-01-01T00:01:00Z"}
	if string(ChallengeCanonical(challenge)) != fixture.CanonicalChallenge || !VerifySignature(fixture.PublicIdentityRef, ChallengeCanonical(challenge), fixture.ChallengeSignature) {
		t.Fatal("cross-language identity fixture challenge did not match")
	}
	heartbeat := Heartbeat{Version: 1, Type: "session.heartbeat", Profile: ProvisionalIdentityProfile, SessionID: "fixture-session", DeviceID: "fixture-device", Sequence: 7, ObservedAt: "2099-01-01T00:02:00Z"}
	if string(HeartbeatCanonical(heartbeat)) != fixture.CanonicalHeartbeat || !VerifySignature(fixture.PublicIdentityRef, HeartbeatCanonical(heartbeat), fixture.HeartbeatSignature) {
		t.Fatal("cross-language identity fixture heartbeat did not match")
	}
}

func TestHeartbeatCanonicalIncludesDisplayMode(t *testing.T) {
	heartbeat := Heartbeat{
		Version: 1, Type: "session.heartbeat", Profile: ProvisionalIdentityProfile,
		SessionID: "fixture-session", DeviceID: "fixture-device", Sequence: 7,
		ObservedAt: "2099-01-01T00:02:00Z", DisplayMode: DisplayModeHeadless,
	}
	legacy := heartbeat
	legacy.DisplayMode = ""
	want := string(HeartbeatCanonical(legacy)) + "displayMode=aGVhZGxlc3M\n"
	if got := string(HeartbeatCanonical(heartbeat)); got != want {
		t.Fatalf("display-mode heartbeat canonical = %q, want %q", got, want)
	}
}

func TestEnrollRejectsNonHTTPSAndDoesNotPersist(t *testing.T) {
	stateDir := tempStateDir(t)
	_, err := (Client{StateDir: stateDir}).Enroll(context.Background(), testOptions("http://example.test"))
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("error = %v, want HTTPS enforcement", err)
	}
	if _, statErr := os.Stat(StatePath(stateDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state path exists after rejected URL: %v", statErr)
	}
}

func TestEnrollRejectsNonOriginInstanceURLs(t *testing.T) {
	for _, instance := range []string{
		"https://control.example/path",
		"https://user:password@control.example",
		"https://control.example?query=1",
		"https://control.example#fragment",
	} {
		t.Run(instance, func(t *testing.T) {
			_, err := (Client{StateDir: tempStateDir(t)}).Enroll(context.Background(), testOptions(instance))
			if err == nil || !strings.Contains(err.Error(), "origin") {
				t.Fatalf("error = %v, want origin validation", err)
			}
		})
	}
}

func TestInstanceOriginCanonicalizationRemovesSlashAndNormalizesHost(t *testing.T) {
	first, err := validateInstance("https://CONTROL.example/")
	if err != nil {
		t.Fatal(err)
	}
	second, err := validateInstance("https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "https://control.example" || second.String() != first.String() {
		t.Fatalf("canonical origins = %q, %q", first, second)
	}
	defaultPort, err := validateInstance("https://control.example:443/")
	if err != nil {
		t.Fatal(err)
	}
	if defaultPort.String() != first.String() {
		t.Fatalf("default HTTPS port was not canonicalized: %q", defaultPort)
	}
}

func TestEnrollRetryReusesExactPendingAttemptWithoutAuthority(t *testing.T) {
	stateDir := tempStateDir(t)
	options := testOptions("https://control.example")
	options.IdempotencyKey = ""
	var firstBody []byte
	var firstHeader string
	first := scriptedDoer(func(request *http.Request) (*http.Response, error) {
		firstBody, _ = io.ReadAll(request.Body)
		firstHeader = request.Header.Get("Idempotency-Key")
		return nil, errors.New("simulated transport failure")
	})
	firstClient := Client{StateDir: stateDir, doer: first, Now: func() time.Time {
		return time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	}}
	if _, err := firstClient.Enroll(context.Background(), options); err == nil {
		t.Fatal("first enrollment unexpectedly succeeded")
	}
	status, _, err := Status(stateDir)
	if err != nil || status != "Unconfigured" {
		t.Fatalf("status after failed attempt = %q, %v", status, err)
	}
	if _, err := LoadAttempt(stateDir); err != nil {
		t.Fatalf("pending attempt missing: %v", err)
	}
	var secondBody []byte
	var secondHeader string
	second := scriptedDoer(func(request *http.Request) (*http.Response, error) {
		secondBody, _ = io.ReadAll(request.Body)
		secondHeader = request.Header.Get("Idempotency-Key")
		var payload Request
		if err := json.Unmarshal(secondBody, &payload); err != nil {
			return nil, err
		}
		return responseFor(request, http.StatusCreated, validResultBody(payload.DeviceID, payload.ExpiresAt)), nil
	})
	secondClient := Client{StateDir: stateDir, doer: second, Now: func() time.Time {
		return time.Date(2026, 8, 24, 10, 1, 0, 0, time.UTC)
	}}
	state, err := secondClient.Enroll(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	var payload Request
	if err := json.Unmarshal(firstBody, &payload); err != nil {
		t.Fatal(err)
	}
	if state.Status != "Pending" || string(firstBody) != string(secondBody) || firstHeader == "" || firstHeader != secondHeader || firstHeader != payload.IdempotencyKey {
		t.Fatalf("retry state/body mismatch: %+v, %q vs %q", state, firstBody, secondBody)
	}
	if _, err := LoadAttempt(stateDir); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("pending attempt remains after retry success: %v", err)
	}
}

func TestEnrollPrintServerBindsRoleAndRejectsKioskRetry(t *testing.T) {
	stateDir := tempStateDir(t)
	options := testOptions("https://control.example")
	options.DeviceKind = DeviceKindPrintServer
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	options.DeviceID = identity.DeviceID
	options.PublicIdentityRef = ""
	options.ProofKind = ""
	options.ProofValue = ""
	options.Identity = &identity
	var firstRequest Request
	client := Client{StateDir: stateDir, doer: scriptedDoer(func(request *http.Request) (*http.Response, error) {
		firstRequest = requestFromHTTP(request)
		return nil, errors.New("simulated transport failure")
	}), Now: func() time.Time {
		return time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	}}
	if _, err := client.Enroll(context.Background(), options); err == nil {
		t.Fatal("print-server enrollment unexpectedly succeeded")
	}
	if firstRequest.DeviceKind != DeviceKindPrintServer || !VerifySignature(identity.PublicIdentityRef, EnrollmentCanonical(firstRequest), firstRequest.Proof.Value) {
		t.Fatalf("print-server request was not role-bound: %+v", firstRequest)
	}
	changed := firstRequest
	changed.DeviceKind = DeviceKindKiosk
	if VerifySignature(identity.PublicIdentityRef, EnrollmentCanonical(changed), firstRequest.Proof.Value) {
		t.Fatal("print-server enrollment signature remained valid after a kiosk role swap")
	}
	networkCalls := 0
	client.doer = scriptedDoer(func(request *http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("must not send role-swapped retry")
	})
	options.DeviceKind = ""
	if _, err := client.Enroll(context.Background(), options); err == nil || !strings.Contains(err.Error(), "different device kind") {
		t.Fatalf("role-swapped retry error = %v", err)
	}
	if networkCalls != 0 {
		t.Fatalf("role-swapped retry made %d network calls", networkCalls)
	}
	options.DeviceKind = DeviceKindPrintServer
	client.doer = scriptedDoer(func(request *http.Request) (*http.Response, error) {
		payload := requestFromHTTP(request)
		return responseFor(request, http.StatusCreated, validResultBody(payload.DeviceID, payload.ExpiresAt)), nil
	})
	state, err := client.Enroll(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if state.DeviceKind != DeviceKindPrintServer {
		t.Fatalf("persisted device kind = %q", state.DeviceKind)
	}
}

func TestEnrollDoesNotOverwriteExistingPendingState(t *testing.T) {
	stateDir := tempStateDir(t)
	client := Client{StateDir: stateDir, doer: scriptedDoer(func(request *http.Request) (*http.Response, error) {
		payload := requestFromHTTP(request)
		return responseFor(request, http.StatusCreated, validResultBody(payload.DeviceID, payload.ExpiresAt)), nil
	}), Now: func() time.Time {
		return time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	}}
	if _, err := client.Enroll(context.Background(), testOptions("https://control.example")); err != nil {
		t.Fatal(err)
	}
	secondCalls := 0
	client.doer = scriptedDoer(func(request *http.Request) (*http.Response, error) {
		secondCalls++
		return nil, errors.New("must not send second enrollment")
	})
	_, err := client.Enroll(context.Background(), testOptions("https://control.example"))
	if !errors.Is(err, ErrAlreadyPending) || secondCalls != 0 {
		t.Fatalf("second enrollment error/calls = %v/%d", err, secondCalls)
	}
}

func TestEnrollRejectsContradictoryResponseExpiryWithoutState(t *testing.T) {
	stateDir := tempStateDir(t)
	client := Client{StateDir: stateDir, doer: scriptedDoer(func(request *http.Request) (*http.Response, error) {
		payload := requestFromHTTP(request)
		mismatchedExpiry := time.Date(2026, 8, 24, 10, 9, 0, 0, time.UTC).Format(time.RFC3339Nano)
		return responseFor(request, http.StatusCreated, validResultBody(payload.DeviceID, mismatchedExpiry)), nil
	}), Now: func() time.Time {
		return time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	}}
	_, err := client.Enroll(context.Background(), testOptions("https://control.example"))
	if err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Fatalf("error = %v, want expiry mismatch", err)
	}
	if _, statErr := os.Stat(StatePath(stateDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state path exists after expiry mismatch: %v", statErr)
	}
}

func TestEnrollUsesTrustedTLSAndPersistsPrivatePendingState(t *testing.T) {
	server, caPath := trustedTLSServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		payload := requestFromHTTP(request)
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(validResultBody(payload.DeviceID, payload.ExpiresAt)))
	}))
	stateDir := tempStateDir(t)
	options := testOptions(server.URL)
	state, err := (Client{StateDir: stateDir, CAPath: caPath, Now: func() time.Time {
		return time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	}}).Enroll(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "Pending" || state.DeviceID != options.DeviceID {
		t.Fatalf("state = %+v", state)
	}
	directoryInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", got)
	}
	stateInfo, err := os.Stat(StatePath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if got := stateInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("state file mode = %o, want 600", got)
	}
	if artifacts, err := filepath.Glob(filepath.Join(stateDir, ".state-*.tmp")); err != nil || len(artifacts) != 0 {
		t.Fatalf("temporary state artifacts = %v, error = %v", artifacts, err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "pending-attempt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending attempt exists after success: %v", err)
	}
	loaded, err := LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EnrollmentID != state.EnrollmentID {
		t.Fatalf("loaded state = %+v", loaded)
	}
}

func TestEnrollRejectsMalformedAndMismatchedResponsesWithoutState(t *testing.T) {
	tests := []struct {
		name string
		doer scriptedDoer
	}{
		{name: "malformed", doer: func(request *http.Request) (*http.Response, error) {
			return responseFor(request, http.StatusOK, "not-json"), nil
		}},
		{name: "mismatched", doer: func(request *http.Request) (*http.Response, error) {
			payload := requestFromHTTP(request)
			return responseFor(request, http.StatusOK, validResultBody("another-device", payload.ExpiresAt)), nil
		}},
		{name: "unknown-authority", doer: func(request *http.Request) (*http.Response, error) {
			payload := requestFromHTTP(request)
			return responseFor(request, http.StatusOK, strings.Replace(validResultBody(payload.DeviceID, payload.ExpiresAt), `"expiresAt"`, `"authority":"managed","expiresAt"`, 1)), nil
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := tempStateDir(t)
			_, err := (Client{StateDir: stateDir, doer: testCase.doer}).Enroll(context.Background(), testOptions("https://control.example"))
			if err == nil {
				t.Fatal("enrollment unexpectedly succeeded")
			}
			if _, statErr := os.Stat(StatePath(stateDir)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("state path exists after malformed response: %v", statErr)
			}
		})
	}
}

func TestEnrollFailureDoesNotLeakResponseBodyOrAuthority(t *testing.T) {
	stateDir := tempStateDir(t)
	_, err := (Client{StateDir: stateDir, doer: scriptedDoer(func(request *http.Request) (*http.Response, error) {
		return responseFor(request, http.StatusBadRequest, `{"authority":"managed","token":"secret-response-body"}`), nil
	})}).Enroll(context.Background(), testOptions("https://control.example"))
	if err == nil {
		t.Fatal("enrollment unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "secret-response-body") || strings.Contains(err.Error(), "managed") {
		t.Fatalf("error leaked response body: %v", err)
	}
	if _, statErr := os.Stat(StatePath(stateDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state path exists after failed enrollment: %v", statErr)
	}
}

func ParsePublicIdentityRef(value string) (ed25519.PublicKey, error) {
	prefix := ProvisionalIdentityProfile + ":"
	if !strings.HasPrefix(value, prefix) || len(value) > 128 {
		return nil, fmt.Errorf("unsupported identity profile")
	}
	key, err := decodeRaw(strings.TrimPrefix(value, prefix), ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("invalid public identity reference")
	}
	return ed25519.PublicKey(key), nil
}

func VerifySignature(publicRef string, canonical []byte, encoded string) bool {
	if identityProfile(publicRef) == P256IdentityProfile {
		return verifyP256Test(publicRef, canonical, encoded)
	}
	publicKey, err := ParsePublicIdentityRef(publicRef)
	if err != nil || len(canonical) == 0 {
		return false
	}
	signature, err := decodeRaw(encoded, ed25519.SignatureSize)
	return err == nil && ed25519.Verify(publicKey, canonical, signature)
}
