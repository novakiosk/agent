package operations

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func policyFiles(t *testing.T, repository string) map[string][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"/etc/containers/policy.json":                 []byte(`{"default":[{"type":"reject"}],"transports":{"docker":{"` + repository + `":[{"type":"sigstoreSigned","keyPath":"` + fleetKeyPath + `","signedIdentity":{"type":"matchRepository"}}]}}}`),
		"/etc/containers/registries.d/novakiosk.yaml": []byte(`{"docker":{"` + repository + `":{"use-sigstore-attachments":true}}}`),
		fleetKeyPath: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}
}
func TestInstalledFleetPolicyDefaultCustomAndRejections(t *testing.T) {
	for _, repository := range []string{"ghcr.io/novakiosk/os", "ghcr.io/example/custom-os"} {
		files := policyFiles(t, repository)
		read := func(path string, _ int) ([]byte, error) { return files[path], nil }
		got, err := fleetPolicyRepository(read)
		if err != nil || got != repository {
			t.Fatal(got, err)
		}
		for _, replacement := range []string{`"type":"insecureAcceptAnything"`, `"type":"signedBy"`} {
			original := files["/etc/containers/policy.json"]
			files["/etc/containers/policy.json"] = []byte(strings.ReplaceAll(string(original), `"type":"sigstoreSigned"`, replacement))
			if _, err := fleetPolicyRepository(read); err == nil {
				t.Fatal("unsafe signature policy accepted")
			}
			files["/etc/containers/policy.json"] = original
		}
		files["/etc/containers/registries.d/novakiosk.yaml"] = []byte(`{"docker":{"ghcr.io/other/os":{"use-sigstore-attachments":true}}}`)
		if _, err := fleetPolicyRepository(read); err == nil {
			t.Fatal("mismatched registry accepted")
		}
	}
	for _, repository := range []string{"ghcr.io/Example/os", "ghcr.io/example/os:latest", "ghcr.io/example/../os", "docker.io/example/os"} {
		if validFleetRepository(repository) {
			t.Fatal(repository)
		}
	}
}
func TestFleetPolicyReadRejectsUnprotectedPaths(t *testing.T) {
	file := t.TempDir() + "/policy"
	if err := os.WriteFile(file, []byte("{}"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readFleetPolicyFile(file, 16384); err == nil {
		t.Fatal("unprotected path accepted")
	}
}
func TestCustomRepositoryPendingCannotSatisfyOtherRepository(t *testing.T) {
	command := fleetFixture(t)
	command.Action = "rollback"
	custom := "ghcr.io/example/os"
	digest := command.Release.ImageDigest
	raw, _ := json.Marshal(map[string]any{"deployments": []any{
		map[string]any{"container-image-reference": "ostree-image-signed:docker://" + custom + "@" + digest, "container-image-reference-digest": digest},
		map[string]any{"booted": true, "container-image-reference": "ostree-image-signed:docker://" + custom + ":latest", "container-image-reference-digest": digest},
	}})
	if _, _, err := fleetDeployments(raw, command.Release.ImageRepository); err == nil {
		t.Fatal("foreign boot accepted")
	}
	_, pending, err := fleetDeployments(raw, custom)
	if err != nil {
		t.Fatal(err)
	}
	if pending == command.PendingIdentity() {
		t.Fatal("foreign pending matched")
	}
	command.Release.ImageRepository = custom
	if pending != command.PendingIdentity() {
		t.Fatal(pending, command.PendingIdentity())
	}
}
func TestForeignRepositoryCommandNeverStagesOrReboots(t *testing.T) {
	c, system, command := fleetSetup(t)
	command.Release.ImageRepository = "ghcr.io/example/os"
	command.PayloadHash = command.Hash()
	if err := c.Accept(command); err != nil {
		t.Fatal(err)
	}
	if err := c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Current().Phase != "failed" || system.stages != 0 || system.reboots != 0 {
		t.Fatal(c.Current())
	}
}

func TestRestartedFleetJournalRejectsSameDigestFromAnotherRepository(t *testing.T) {
	for _, phase := range []string{"executing", "staged"} {
		t.Run(phase, func(t *testing.T) {
			c, system, command := fleetSetup(t)
			if err := c.persist(FleetJournal{Version: 1, Command: command, Phase: phase}); err != nil {
				t.Fatal(err)
			}
			other := command
			other.Release.ImageRepository = "ghcr.io/example/os"
			system.boot.Release.ImageRepository = other.Release.ImageRepository
			system.pending = other.PendingIdentity()
			recovered, err := NewFleetCoordinator(c.stateDir, system, c.clock)
			if err != nil {
				t.Fatal(err)
			}
			stepFleet(t, recovered)
			if recovered.Current().Phase != "unknown" || system.reboots != 0 || system.stages != 0 {
				t.Fatal(recovered.Current())
			}
		})
	}
}
