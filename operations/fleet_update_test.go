package operations

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func fleetFixture(t *testing.T) UpdateCommand {
	t.Helper()
	raw, err := os.ReadFile("../fixtures/fleet-update-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Command     UpdateCommand
		Release     Release
		ReleaseHash string
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Release.Hash() != f.ReleaseHash || f.Command.Hash() != f.Command.PayloadHash {
		t.Fatal("shared canonical hash mismatch")
	}
	return f.Command
}

type fakeFleet struct {
	mu                  sync.Mutex
	boot                BootRelease
	pending             string
	observeErr          error
	active              bool
	stages, reboots     int
	stageErr, rebootErr error
	entered             chan struct{}
	release             chan struct{}
}

func (f *fakeFleet) Observe(context.Context) (BootRelease, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boot, f.pending, f.observeErr
}
func (f *fakeFleet) Active(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active, nil
}
func (f *fakeFleet) Stage(context.Context, UpdateCommand) error {
	f.mu.Lock()
	f.stages++
	f.mu.Unlock()
	if f.entered != nil {
		close(f.entered)
	}
	if f.release != nil {
		<-f.release
	}
	return f.stageErr
}
func (f *fakeFleet) Reboot(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reboots++
	return f.rebootErr
}
func fleetSetup(t *testing.T) (*FleetCoordinator, *fakeFleet, UpdateCommand) {
	t.Helper()
	command := fleetFixture(t)
	now, _ := time.Parse(time.RFC3339, command.IssuedAt)
	system := &fakeFleet{boot: BootRelease{UpdateMode: "automatic", BootID: command.BootIDBefore, Release: command.Release}}
	system.boot.Release.ImageDigest = "sha256:" + strings.Repeat("2", 64)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := NewFleetCoordinator(dir, system, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return c, system, command
}
func stepFleet(t *testing.T, c *FleetCoordinator) {
	t.Helper()
	if err := c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestFleetSelectedImageCrashAndReboot(t *testing.T) {
	c, f, command := fleetSetup(t)
	if err := c.Accept(command); err != nil {
		t.Fatal(err)
	}
	// Accepted delivery survives expiry and process restart before any effects.
	c.clock = func() time.Time {
		issued, _ := time.Parse(time.RFC3339, command.IssuedAt)
		return issued.Add(10 * time.Minute)
	}
	var err error
	c, err = NewFleetCoordinator(c.stateDir, f, c.clock)
	if err != nil {
		t.Fatal(err)
	}
	f.entered = make(chan struct{})
	f.release = make(chan struct{})
	stepFleet(t, c)
	<-f.entered
	if c.Current().Phase != "executing" {
		t.Fatal(c.Current())
	}
	recovered, err := NewFleetCoordinator(c.stateDir, f, c.clock)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.active = true
	f.mu.Unlock()
	stepFleet(t, recovered)
	if recovered.Current().Phase != "executing" || !recovered.Busy() {
		t.Fatal("active helper released execution")
	}
	close(f.release)
	f.mu.Lock()
	f.active = false
	f.pending = command.PendingIdentity()
	f.mu.Unlock()
	stepFleet(t, recovered)
	if recovered.Current().Phase != "staged" {
		t.Fatal(recovered.Current())
	}
	stepFleet(t, recovered)
	if recovered.Current().Phase != "reboot-intent" {
		t.Fatal(recovered.Current())
	}
	recovered, err = NewFleetCoordinator(c.stateDir, f, c.clock)
	if err != nil {
		t.Fatal(err)
	}
	stepFleet(t, recovered)
	f.mu.Lock()
	if f.stages != 1 || f.reboots != 1 {
		t.Fatal("effect repeated")
	}
	f.boot = BootRelease{UpdateMode: "automatic", BootID: "00000000-0000-4000-8000-000000000003", Release: command.Release}
	f.pending = ""
	f.mu.Unlock()
	stepFleet(t, recovered)
	if recovered.Current().Phase != "applied" || !recovered.Busy() {
		t.Fatal("lost report cannot resolve journal")
	}
	if err := RequireResolvedForRotation(c.stateDir, c.clock()); err == nil {
		t.Fatal("rotation discarded unacknowledged evidence")
	}
	recovered, err = NewFleetCoordinator(c.stateDir, f, c.clock)
	if err != nil {
		t.Fatal(err)
	}
	stepFleet(t, recovered)
	if err = recovered.Acknowledge(command.CommandID, "applied"); err != nil {
		t.Fatal(err)
	}
	if err = RequireResolvedForRotation(c.stateDir, c.clock()); err != nil {
		t.Fatal(err)
	}
}
func TestFleetRecoveryDoesNotRepeatReboot(t *testing.T) {
	c, f, command := fleetSetup(t)
	reason := "reboot_unresolved"
	if err := c.persist(FleetJournal{Version: 1, Command: command, Phase: "unknown", Error: &reason}); err != nil {
		t.Fatal(err)
	}
	f.pending = command.PendingIdentity()
	for range 3 {
		stepFleet(t, c)
	}
	if f.reboots != 0 || c.Current().Phase != "unknown" || !c.Busy() {
		t.Fatal("uncertain reboot repeated")
	}
}
func TestFleetMismatchAndPending(t *testing.T) {
	for _, change := range []string{"digest", "mode", "pending", "already-current"} {
		t.Run(change, func(t *testing.T) {
			c, f, command := fleetSetup(t)
			if err := c.Accept(command); err != nil {
				t.Fatal(err)
			}
			f.boot.Release = command.Release
			if change == "pending" {
				f.pending = "sha256:" + strings.Repeat("a", 64)
			} else if change != "already-current" {
				f.boot.BootID = "00000000-0000-4000-8000-000000000009"
				switch change {
				case "digest":
					f.boot.Release.ImageDigest = "sha256:" + strings.Repeat("a", 64)
				case "mode":
					f.boot.UpdateMode = "held"
				}
			}
			stepFleet(t, c)
			expected := "failed"
			if change == "already-current" {
				expected = "already-current"
			}
			if c.Current().Phase != expected || f.stages != 0 || f.reboots != 0 {
				t.Fatal(c.Current())
			}
		})
	}
}
func TestFleetUnknownTransactionAndSafeFailure(t *testing.T) {
	c, f, command := fleetSetup(t)
	if err := c.persist(FleetJournal{Version: 1, Command: command, Phase: "executing"}); err != nil {
		t.Fatal(err)
	}
	f.observeErr = errors.New("rpm-ostreed still active")
	stepFleet(t, c)
	if c.Current().Phase != "unknown" || !c.Busy() {
		t.Fatal(c.Current())
	}
	f.observeErr = nil
	stepFleet(t, c)
	if c.Current().Phase != "failed" || f.stages != 0 {
		t.Fatal(c.Current())
	}
}
func TestFleetAdmissionAndPrivateFiles(t *testing.T) {
	c, _, command := fleetSetup(t)
	expired := command
	expired.ExpiresAt = expired.IssuedAt
	expired.PayloadHash = expired.Hash()
	if c.Accept(expired) == nil {
		t.Fatal("accepted expired")
	}
	if c.Accept(command) != nil {
		t.Fatal("valid command")
	}
	conflict := command
	conflict.Release.ImageDigest = "sha256:" + strings.Repeat("3", 64)
	conflict.PayloadHash = conflict.Hash()
	if !errors.Is(c.Accept(conflict), ErrCommandConflict) {
		t.Fatal("rebound command")
	}
	conflict.CommandID = "00000000-0000-4000-8000-000000000099"
	conflict.PayloadHash = conflict.Hash()
	if !errors.Is(c.Accept(conflict), ErrCommandBusy) {
		t.Fatal("overlapping command")
	}
	raw, _ := os.ReadFile(filepath.Join(c.stateDir, FleetJournalName))
	if ValidateResolvedFleetJournal(raw, c.clock()) == nil {
		t.Fatal("migrated pending journal")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.stateDir, FleetJournalName)
	os.Remove(path)
	os.Symlink(target, path)
	if _, err := NewFleetCoordinator(c.stateDir, c.system, c.clock); err == nil {
		t.Fatal("followed symlink")
	}
	if fleetAtomic(path, []byte("changed")) == nil {
		t.Fatal("replaced symlink")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "untouched" {
		t.Fatal("changed foreign file")
	}
}
func TestFleetDeploymentEvidence(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	deployment := map[string]any{"booted": true, "container-image-reference": "ostree-image-signed:docker://ghcr.io/novakiosk/os@" + digest, "container-image-reference-digest": digest}
	encode := func(transaction any) []byte {
		raw, _ := json.Marshal(map[string]any{"transaction": transaction, "deployments": []any{deployment}})
		return raw
	}
	if got, pending, err := fleetDeployments(encode(nil), "ghcr.io/novakiosk/os"); err != nil || got != digest || pending != "" {
		t.Fatal(got, pending, err)
	}
	if _, _, err := fleetDeployments(encode([]string{"upgrade"}), "ghcr.io/novakiosk/os"); err == nil {
		t.Fatal("active backend treated as settled")
	}
	deployment["container-image-reference"] = "ostree-unverified-registry:evil/image@" + digest
	if _, _, err := fleetDeployments(encode(nil), "ghcr.io/novakiosk/os"); err == nil {
		t.Fatal("untrusted image accepted")
	}
}

type rootFleetInfo struct{ fakeInfo }

func (rootFleetInfo) Sys() any { return &syscall.Stat_t{Uid: 0} }
func TestFleetEligibilityMarkerAndLegacyGuard(t *testing.T) {
	stat := func(string) (os.FileInfo, error) { return rootFleetInfo{fakeInfo{mode: 0755}}, nil }
	for _, marker := range []string{"", "1\n", "fleet-update-v1\n", "fleet-update-v2\n"} {
		supported := fleetUpdateSupported(func(string) ([]byte, error) { return []byte(marker), nil }, stat)
		if supported != (marker == "fleet-update-v1\n") {
			t.Fatalf("marker %q support=%v", marker, supported)
		}
	}
	if fleetUpdateSupported(func(string) ([]byte, error) { return []byte("fleet-update-v1\n"), nil }, func(path string) (os.FileInfo, error) {
		if path == UpdateHelperPath {
			return nil, os.ErrNotExist
		}
		return stat(path)
	}) {
		t.Fatal("missing helper advertised")
	}
	fs := newFakeFS()
	fs.files["/usr/share/novakiosk/fleet-update-protocol"] = []byte("fleet-update-v1\n")
	called := false
	executor := NewExecutor(OperationConfig{FS: fs, Runner: RunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		called = true
		return nil, nil, nil
	})})
	result := executor.Execute(context.Background(), CommandSystemUpdate)
	if result.ErrorCategory == nil || *result.ErrorCategory != ErrorInvalidCommand || called {
		t.Fatal("legacy command consumed typed request")
	}
}

func TestFleetObservedSignedOrigins(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, reference := range []string{"ostree-image-signed:docker://ghcr.io/novakiosk/os@" + digest, "ostree-image-signed:docker://ghcr.io/novakiosk/os:latest", "ostree-image-signed:registry:ghcr.io/novakiosk/os:latest"} {
		if !signedFleetReference(reference, digest, "ghcr.io/novakiosk/os") {
			t.Fatal(reference)
		}
	}
	for _, reference := range []string{"ostree-unverified-registry:ghcr.io/novakiosk/os:latest", "ostree-image-signed:docker://ghcr.io/novakiosk/os-evil:latest", "ostree-image-signed:docker://ghcr.io/novakiosk/os@sha256:" + strings.Repeat("b", 64), "ostree-image-signed:registry:ghcr.io/novakiosk/os:bad tag"} {
		if signedFleetReference(reference, digest, "ghcr.io/novakiosk/os") {
			t.Fatal(reference)
		}
	}
}
func TestFleetJournalRejectsInventedSuccess(t *testing.T) {
	c, _, command := fleetSetup(t)
	j := FleetJournal{Version: 1, Command: command, Phase: "applied", Boot: &BootRelease{UpdateMode: "automatic", BootID: command.BootIDBefore, Release: command.Release}, Acknowledged: true}
	raw, _ := json.Marshal(j)
	if ValidateResolvedFleetJournal(raw, c.clock()) == nil {
		t.Fatal("accepted applied on same boot")
	}
	j.Phase = "already-current"
	raw, _ = json.Marshal(j)
	if ValidateResolvedFleetJournal(raw, c.clock()) != nil {
		t.Fatal("valid resolved journal rejected")
	}
	j.Boot.Release.ImageDigest = strings.Repeat("0", 64)
	raw, _ = json.Marshal(j)
	if ValidateResolvedFleetJournal(raw, c.clock()) == nil {
		t.Fatal("accepted mismatched binary hash")
	}
}

func TestFleetStagedEvidenceLossBlocksReboot(t *testing.T) {
	c, f, command := fleetSetup(t)
	if err := c.persist(FleetJournal{Version: 1, Command: command, Phase: "staged"}); err != nil {
		t.Fatal(err)
	}
	f.pending = "conflicting"
	stepFleet(t, c)
	if c.Current().Phase != "unknown" || !c.Busy() || f.reboots != 0 {
		t.Fatal("stale stage evidence allowed reboot")
	}
	f.pending = command.PendingIdentity()
	stepFleet(t, c)
	if c.Current().Phase != "staged" {
		t.Fatal("fresh exact stage could not recover")
	}
}

func TestFleetResumeSameDigestChangesMode(t *testing.T) {
	c, f, command := fleetSetup(t)
	command.Action = "resume"
	command.PayloadHash = command.Hash()
	f.boot.Release = command.Release
	f.boot.UpdateMode = "held"
	if err := c.Accept(command); err != nil {
		t.Fatal(err)
	}
	stepFleet(t, c)
	if c.Current().Phase != "executing" {
		t.Fatal("same image must change held origin", c.Current())
	}
	f.mu.Lock()
	f.pending = command.PendingIdentity()
	f.mu.Unlock()
	// Stage is asynchronous; observe its completion through the coordinator.
	deadline := time.Now().Add(time.Second)
	for c.Current().Phase == "executing" && time.Now().Before(deadline) {
		stepFleet(t, c)
		time.Sleep(time.Millisecond)
	}
	if c.Current().Phase != "staged" {
		t.Fatal(c.Current())
	}
	f.mu.Lock()
	f.boot.BootID = "00000000-0000-4000-8000-000000000009"
	f.pending = ""
	f.mu.Unlock()
	stepFleet(t, c)
	if c.Current().Phase != "failed" {
		t.Fatal("held boot cannot prove resume", c.Current())
	}
}

func TestFleetModeBoundIntoCommandAndEvidence(t *testing.T) {
	command := fleetFixture(t)
	hash := command.Hash()
	command.Action = "rollback"
	if command.Hash() == hash {
		t.Fatal("action not bound")
	}
	boot := BootRelease{BootID: command.BootIDBefore, Release: command.Release, UpdateMode: "automatic"}
	if command.MatchesBoot(boot) {
		t.Fatal("rollback accepted tracking origin")
	}
	boot.UpdateMode = "held"
	if !command.MatchesBoot(boot) {
		t.Fatal("exact held image rejected")
	}
}

func TestFleetDisplayMetadataDoesNotChangeTargetIdentity(t *testing.T) {
	command := fleetFixture(t)
	boot := BootRelease{BootID: command.BootIDBefore, Release: command.Release, UpdateMode: "automatic", Versions: &BootVersions{OS: "44.20261005.1", Agent: "development", Novakeys: "1.0.0"}}
	if !boot.Versions.Valid() || !command.MatchesBoot(boot) {
		t.Fatal("display metadata changed image identity")
	}
	boot.Versions.Agent = "different"
	if !command.MatchesBoot(boot) {
		t.Fatal("display version constrained exact image match")
	}
	boot.Versions.OS = "bad\nversion"
	if boot.Versions.Valid() {
		t.Fatal("unsafe display version")
	}
	raw := []byte(`{"deployments":[{"booted":false,"version":"old"},{"booted":true,"version":"44.20261005.1"}]}`)
	if bootOSVersion(raw) != "44.20261005.1" {
		t.Fatal("wrong boot version")
	}
}
