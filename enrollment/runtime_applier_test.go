package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
)

type runtimeCommandCall struct {
	name        string
	args        []string
	environment []string
}

type runtimeCommandRecorder struct {
	mu       sync.Mutex
	calls    []runtimeCommandCall
	failName string
}

func (runner *runtimeCommandRecorder) Run(_ context.Context, name string, args []string, environment []string) ([]byte, error) {
	runner.mu.Lock()
	runner.calls = append(runner.calls, runtimeCommandCall{name: name, args: append([]string(nil), args...), environment: append([]string(nil), environment...)})
	runner.mu.Unlock()
	if name == runner.failName {
		return []byte("bounded failure"), errors.New("command failed")
	}
	return nil, nil
}

func runtimeTestArtifact(withNovaKeys bool, layouts []RuntimeLayout) RuntimeArtifact {
	novaLine := ""
	if withNovaKeys {
		novaLine = "\nexec_always --no-startup-id ~/.local/bin/novakeys"
	}
	artifact := RuntimeArtifact{
		Version: ProtocolVersion, Type: "runtime.config", Status: "ready", ArtifactRevision: "0-test",
		Sway:     &RuntimeComponent{Revision: 0, SourceRevision: 0, Source: "global", Mode: "raw", Text: "# test" + novaLine + "\n# Raw Sway expert configuration\n"},
		NOVAKeys: &RuntimeComponent{Revision: 0, SourceRevision: 0, Source: "global", Mode: "raw", Text: "show_language_switcher = true\n"},
		Layouts:  layouts,
	}
	artifact.ArtifactHash = RuntimeArtifactHash(artifact)
	return artifact
}

func TestValidateRuntimeArtifactUsesASCIILayoutOrdering(t *testing.T) {
	artifact := runtimeTestArtifact(false, []RuntimeLayout{
		{LanguageCode: "aa-9a", TOML: "layout = 1\n"},
		{LanguageCode: "aa-a1", TOML: "layout = 2\n"},
		{LanguageCode: "aa9a", TOML: "layout = 3\n"},
	})
	if err := ValidateRuntimeArtifact(artifact); err != nil {
		t.Fatalf("ASCII-ordered layout artifact rejected: %v", err)
	}
	artifact.Layouts[0], artifact.Layouts[1] = artifact.Layouts[1], artifact.Layouts[0]
	artifact.ArtifactHash = RuntimeArtifactHash(artifact)
	if err := ValidateRuntimeArtifact(artifact); err == nil {
		t.Fatal("non-ASCII-lexical layout ordering was accepted")
	}
}

func runtimeExecutable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "novakeys")
	if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runtimeDirForTest(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "runtime")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func runtimeGenerationSnapshot(t *testing.T, configDir string, layoutCodes []string) map[string][]byte {
	t.Helper()
	relativePaths := []string{"sway/config", "novakeys/config", "novakeys/" + runtimeManifestName}
	for _, code := range layoutCodes {
		relativePaths = append(relativePaths, "novakeys/layout-"+code+".toml")
	}
	snapshot := make(map[string][]byte, len(relativePaths))
	for _, relative := range relativePaths {
		path := filepath.Join(configDir, filepath.FromSlash(relative))
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			snapshot[relative] = nil
			continue
		}
		if err != nil {
			t.Fatalf("read runtime generation %s: %v", relative, err)
		}
		snapshot[relative] = append([]byte(nil), data...)
	}
	return snapshot
}

func assertRuntimeGeneration(t *testing.T, want, got map[string][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("runtime generation file count = %d, want %d (%v)", len(got), len(want), got)
	}
	for path, expected := range want {
		if actual, ok := got[path]; !ok || !bytes.Equal(actual, expected) {
			t.Errorf("runtime generation %s = %q, want %q", path, actual, expected)
		}
	}
}

func runtimeReloadCount(runner *runtimeCommandRecorder) int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	count := 0
	for _, call := range runner.calls {
		if call.name == "/usr/bin/swaymsg" && len(call.args) == 1 && call.args[0] == "reload" {
			count++
		}
	}
	return count
}

func runtimeTestApplier(t *testing.T, configDir string, runner *runtimeCommandRecorder, hook RuntimeTransactionHook) *SwayRuntimeApplier {
	return runtimeTestApplierWithNova(t, configDir, runner, hook, "")
}

func runtimeTestApplierWithNova(t *testing.T, configDir string, runner *runtimeCommandRecorder, hook RuntimeTransactionHook, novaKeysBinary string) *SwayRuntimeApplier {
	t.Helper()
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(configDir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	applier, err := NewSwayRuntimeApplier(RuntimeApplierOptions{
		ConfigDir: configDir, CommandRunner: runner, SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil }, TransactionHook: hook, NovaKeysBinary: novaKeysBinary,
		RuntimeDirPath: func(int) string { return runtimeDir },
	})
	if err != nil {
		t.Fatal(err)
	}
	return applier
}

func completeRuntimeRecoveryForTest(t *testing.T, configDir string, runner *runtimeCommandRecorder) {
	t.Helper()
	recovery, err := recoverRuntimeTransaction(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.NeedsReload {
		if err := runtimeTestApplier(t, configDir, runner, nil).finishRuntimeRecovery(context.Background(), recovery); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSwayRuntimeTransactionRecoversPreparedJournal(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, ".config")
	runner := &runtimeCommandRecorder{}
	oldArtifact := runtimeTestArtifact(false, []RuntimeLayout{{LanguageCode: "en", TOML: "old = true\n"}})
	newArtifact := runtimeTestArtifact(false, []RuntimeLayout{{LanguageCode: "no", TOML: "new = true\n"}})
	if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), oldArtifact); err != nil {
		t.Fatal(err)
	}
	oldGeneration := runtimeGenerationSnapshot(t, configDir, []string{"en", "no"})
	reloads := runtimeReloadCount(runner)
	faulted := runtimeTestApplier(t, configDir, runner, func(stage string) error {
		if stage == runtimeTransactionPersistedStage {
			return ErrRuntimeTransactionInterrupted
		}
		return nil
	})
	if err := faulted.Apply(context.Background(), newArtifact); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
		t.Fatalf("persisted-journal interruption = %v", err)
	}
	if _, err := os.Stat(runtimeTransactionJournalPath(configDir)); err != nil {
		t.Fatalf("transaction journal after interruption: %v", err)
	}
	assertRuntimeGeneration(t, oldGeneration, runtimeGenerationSnapshot(t, configDir, []string{"en", "no"}))
	if got := runtimeReloadCount(runner); got != reloads {
		t.Fatalf("reloads before activation = %d, want %d", got, reloads)
	}
	completeRuntimeRecoveryForTest(t, configDir, runner)
	if _, err := os.Stat(runtimeTransactionJournalPath(configDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal after recovery = %v", err)
	}
	if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), newArtifact); err != nil {
		t.Fatal(err)
	}
	newGeneration := runtimeGenerationSnapshot(t, configDir, []string{"en", "no"})
	if newGeneration["novakeys/layout-en.toml"] != nil || string(newGeneration["novakeys/layout-no.toml"]) != "new = true\n" {
		t.Fatalf("new generation layouts = %+v", newGeneration)
	}
}

func TestSwayRuntimeTransactionRecoversAfterEveryReplacementAndRemoval(t *testing.T) {
	stages := []string{
		"replacement:novakeys/" + runtimeManifestName,
		"replacement:novakeys/config",
		"replacement:novakeys/layout-no.toml",
		"replacement:novakeys/layout-sv.toml",
		"replacement:sway/config",
		"removal:novakeys/layout-en.toml",
	}
	for _, targetStage := range stages {
		t.Run(targetStage, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, ".config")
			runner := &runtimeCommandRecorder{}
			oldArtifact := runtimeTestArtifact(false, []RuntimeLayout{{LanguageCode: "en", TOML: "old-en = true\n"}, {LanguageCode: "no", TOML: "old-no = true\n"}})
			newArtifact := runtimeTestArtifact(false, []RuntimeLayout{{LanguageCode: "no", TOML: "new-no = true\n"}, {LanguageCode: "sv", TOML: "new-sv = true\n"}})
			if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), oldArtifact); err != nil {
				t.Fatal(err)
			}
			oldGeneration := runtimeGenerationSnapshot(t, configDir, []string{"en", "no", "sv"})
			hook := func(stage string) error {
				if stage == targetStage {
					return ErrRuntimeTransactionInterrupted
				}
				return nil
			}
			if err := runtimeTestApplier(t, configDir, runner, hook).Apply(context.Background(), newArtifact); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
				t.Fatalf("%s interruption = %v", targetStage, err)
			}
			if got := runtimeReloadCount(runner); got != 1 {
				t.Fatalf("reloads before %s = %d, want 1", targetStage, got)
			}
			completeRuntimeRecoveryForTest(t, configDir, runner)
			assertRuntimeGeneration(t, oldGeneration, runtimeGenerationSnapshot(t, configDir, []string{"en", "no", "sv"}))
			if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), newArtifact); err != nil {
				t.Fatal(err)
			}
			newGeneration := runtimeGenerationSnapshot(t, configDir, []string{"en", "no", "sv"})
			if newGeneration["novakeys/layout-en.toml"] != nil || string(newGeneration["novakeys/layout-no.toml"]) != "new-no = true\n" || string(newGeneration["novakeys/layout-sv.toml"]) != "new-sv = true\n" {
				t.Fatal("retired layout remained after committed generation")
			}
		})
	}
}

func TestSwayRuntimeTransactionRecoversBeforeAndAfterReload(t *testing.T) {
	for _, targetStage := range []string{runtimeTransactionBeforeReloadStage, runtimeTransactionAfterReloadStage} {
		t.Run(targetStage, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, ".config")
			runner := &runtimeCommandRecorder{}
			oldArtifact := runtimeTestArtifact(false, nil)
			newArtifact := runtimeTestArtifact(false, nil)
			newArtifact.Sway.Text = strings.Replace(newArtifact.Sway.Text, "# test", "# new", 1)
			newArtifact.ArtifactHash = RuntimeArtifactHash(newArtifact)
			if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), oldArtifact); err != nil {
				t.Fatal(err)
			}
			oldGeneration := runtimeGenerationSnapshot(t, configDir, nil)
			hook := func(stage string) error {
				if stage == targetStage {
					return ErrRuntimeTransactionInterrupted
				}
				return nil
			}
			if err := runtimeTestApplier(t, configDir, runner, hook).Apply(context.Background(), newArtifact); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
				t.Fatalf("%s interruption = %v", targetStage, err)
			}
			completeRuntimeRecoveryForTest(t, configDir, runner)
			assertRuntimeGeneration(t, oldGeneration, runtimeGenerationSnapshot(t, configDir, nil))
		})
	}
}

func TestSwayRuntimeRecoveryAfterReloadCompletesBeforeRejectingNextArtifact(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, ".config")
	runner := &runtimeCommandRecorder{}
	oldArtifact := runtimeTestArtifact(false, nil)
	newArtifact := runtimeTestArtifact(false, nil)
	newArtifact.Sway.Text = strings.Replace(newArtifact.Sway.Text, "# test", "# new-active", 1)
	newArtifact.ArtifactHash = RuntimeArtifactHash(newArtifact)
	if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), oldArtifact); err != nil {
		t.Fatal(err)
	}
	if err := runtimeTestApplier(t, configDir, runner, func(stage string) error {
		if stage == runtimeTransactionAfterReloadStage {
			return ErrRuntimeTransactionInterrupted
		}
		return nil
	}).Apply(context.Background(), newArtifact); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
		t.Fatalf("after-reload interruption = %v", err)
	}
	if got := runtimeReloadCount(runner); got != 2 {
		t.Fatalf("reloads after interrupted activation = %d, want 2", got)
	}
	blocked := newArtifact
	blocked.Status = "blocked"
	blocked.Sway = nil
	blocked.NOVAKeys = nil
	reason := "runtime-presentation-assignment-missing"
	blocked.BlockedReason = &reason
	blocked.ArtifactHash = RuntimeArtifactHash(blocked)
	if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), blocked); err == nil {
		t.Fatal("blocked artifact unexpectedly applied")
	}
	if got := runtimeReloadCount(runner); got != 3 {
		t.Fatalf("recovery did not reload restored old config before validation: %d reloads", got)
	}
	oldGeneration := runtimeGenerationSnapshot(t, configDir, nil)
	if !strings.Contains(string(oldGeneration["sway/config"]), "# test") {
		t.Fatalf("restored config = %q", oldGeneration["sway/config"])
	}
	if _, err := os.Stat(runtimeTransactionJournalPath(configDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal after rejected artifact = %v", err)
	}
}

func TestSwayRuntimeRecoveryReconcilesNOVAKeys(t *testing.T) {
	for _, novaKeysEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[novaKeysEnabled], func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, ".config")
			runner := &runtimeCommandRecorder{}
			novaKeysBinary := runtimeExecutable(t)
			oldArtifact := runtimeTestArtifact(novaKeysEnabled, nil)
			newArtifact := runtimeTestArtifact(novaKeysEnabled, nil)
			newArtifact.Sway.Text = strings.Replace(newArtifact.Sway.Text, "# test", "# newer", 1)
			newArtifact.ArtifactHash = RuntimeArtifactHash(newArtifact)
			if err := runtimeTestApplierWithNova(t, configDir, runner, nil, novaKeysBinary).Apply(context.Background(), oldArtifact); err != nil {
				t.Fatal(err)
			}
			if err := runtimeTestApplierWithNova(t, configDir, runner, func(stage string) error {
				if stage == runtimeTransactionBeforeCommitStage {
					return ErrRuntimeTransactionInterrupted
				}
				return nil
			}, novaKeysBinary).Apply(context.Background(), newArtifact); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
				t.Fatalf("after-reload interruption = %v", err)
			}
			blocked := newArtifact
			blocked.Status = "blocked"
			blocked.Sway = nil
			blocked.NOVAKeys = nil
			reason := "runtime-presentation-assignment-missing"
			blocked.BlockedReason = &reason
			blocked.ArtifactHash = RuntimeArtifactHash(blocked)
			if err := runtimeTestApplierWithNova(t, configDir, runner, nil, novaKeysBinary).Apply(context.Background(), blocked); err == nil {
				t.Fatal("blocked artifact unexpectedly applied")
			}
			novaMessages := map[string]int{}
			runner.mu.Lock()
			for _, call := range runner.calls {
				if call.name == novaKeysBinary && len(call.args) == 2 && call.args[0] == "-m" {
					novaMessages[call.args[1]]++
				}
			}
			runner.mu.Unlock()
			wantMessage := "close"
			if novaKeysEnabled {
				wantMessage = "reload-config"
			}
			if novaMessages[wantMessage] != 3 {
				t.Fatalf("NOVA Keys %s calls = %d, want 3", wantMessage, novaMessages[wantMessage])
			}
		})
	}
}

func TestSwayRuntimeTransactionCommittedJournalRetainsCoherentNewGeneration(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, ".config")
	runner := &runtimeCommandRecorder{}
	oldArtifact := runtimeTestArtifact(false, nil)
	newArtifact := runtimeTestArtifact(false, nil)
	newArtifact.Sway.Text = strings.Replace(newArtifact.Sway.Text, "# test", "# committed", 1)
	newArtifact.ArtifactHash = RuntimeArtifactHash(newArtifact)
	if err := runtimeTestApplier(t, configDir, runner, nil).Apply(context.Background(), oldArtifact); err != nil {
		t.Fatal(err)
	}
	if err := runtimeTestApplier(t, configDir, runner, func(stage string) error {
		if stage == runtimeTransactionCommittedStage {
			return ErrRuntimeTransactionInterrupted
		}
		return nil
	}).Apply(context.Background(), newArtifact); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
		t.Fatalf("committed-journal interruption = %v", err)
	}
	newGeneration := runtimeGenerationSnapshot(t, configDir, nil)
	completeRuntimeRecoveryForTest(t, configDir, runner)
	assertRuntimeGeneration(t, newGeneration, runtimeGenerationSnapshot(t, configDir, nil))
	if _, err := os.Stat(runtimeTransactionJournalPath(configDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed journal remains after recovery: %v", err)
	}
}

func TestSwayRuntimeTransactionRejectsSymlinkCorruptAndOversizedJournal(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, ".config")
	if err := os.MkdirAll(filepath.Join(configDir, "novakeys", "sway"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(configDir, "sway"), 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := runtimeTransactionJournalPath(configDir)
	if err := os.WriteFile(journalPath, []byte(`{"version":1,"phase":"prepared","artifactHash":"bad","entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverRuntimeTransaction(configDir); err == nil {
		t.Fatal("corrupt journal unexpectedly recovered")
	}
	// Capture a valid prepared journal so syntax validation cannot mask the
	// byte limit or symlink checks below.
	applier := runtimeTestApplier(t, configDir, &runtimeCommandRecorder{}, func(stage string) error {
		if stage == runtimeTransactionPersistedStage {
			return ErrRuntimeTransactionInterrupted
		}
		return nil
	})
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), runtimeTestArtifact(false, nil)); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
		t.Fatalf("create prepared journal: %v", err)
	}
	validJournal, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverRuntimeTransaction(configDir); err != nil {
		t.Fatalf("valid journal recovery: %v", err)
	}
	oversized := append(append([]byte(nil), validJournal...), bytes.Repeat([]byte(" "), runtimeTransactionMaxJournalBytes+1-len(validJournal))...)
	if err := os.WriteFile(journalPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverRuntimeTransaction(configDir); err == nil {
		t.Fatal("oversized journal unexpectedly recovered")
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "journal-target")
	if err := os.WriteFile(target, validJournal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, journalPath); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverRuntimeTransaction(configDir); err == nil {
		t.Fatal("symlink journal unexpectedly recovered")
	}
}

func TestSwayRuntimeApplierStagesReloadsAndCleansOnlyOwnedLayouts(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, ".config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &runtimeCommandRecorder{}
	novaKeysPath := runtimeExecutable(t)
	runtimeDir := runtimeDirForTest(t, root)
	applier, err := NewSwayRuntimeApplier(RuntimeApplierOptions{
		ConfigDir: configDir, CommandRunner: runner, SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil }, NovaKeysBinary: novaKeysPath,
		RuntimeDirPath: func(int) string { return runtimeDir },
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := runtimeTestArtifact(true, []RuntimeLayout{{LanguageCode: "en", TOML: "layout = true\n"}, {LanguageCode: "no", TOML: "layout = false\n"}})
	if err := applier.Apply(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(configDir); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("config parent mode changed: %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "sway", "config")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "novakeys", "layout-en.toml")); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(configDir, "novakeys", runtimeManifestName))
	if err != nil || !strings.Contains(string(manifest), "layout-en.toml") && !strings.Contains(string(manifest), "\"en\"") {
		t.Fatalf("manifest = %q, %v", manifest, err)
	}

	unmanaged := filepath.Join(configDir, "novakeys", "layout-fr.toml")
	if err := os.WriteFile(unmanaged, []byte("unmanaged = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := runtimeTestArtifact(false, []RuntimeLayout{{LanguageCode: "sv", TOML: "layout = true\n"}})
	if err := applier.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "novakeys", "layout-en.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old managed layout still exists: %v", err)
	}
	runner.mu.Lock()
	calls := append([]runtimeCommandCall(nil), runner.calls...)
	runner.mu.Unlock()
	seenReloadConfig, seenClose := false, false
	for _, call := range calls {
		if len(call.args) == 2 && call.args[0] == "-m" && call.args[1] == "reload-config" {
			seenReloadConfig = true
		}
		if len(call.args) == 2 && call.args[0] == "-m" && call.args[1] == "close" {
			seenClose = true
		}
	}
	if data, err := os.ReadFile(unmanaged); err != nil || string(data) != "unmanaged = true\n" {
		t.Fatalf("unmanaged layout changed: %q, %v", data, err)
	}
	if seenReloadConfig == false || seenClose == false {
		t.Fatalf("runtime process calls missing: %+v", calls)
	}
}

func TestSwayRuntimeApplierRollsBackWhenReloadFails(t *testing.T) {
	root := t.TempDir()
	runner := &runtimeCommandRecorder{failName: "/usr/bin/swaymsg"}
	runtimeDir := runtimeDirForTest(t, root)
	applier, err := NewSwayRuntimeApplier(RuntimeApplierOptions{ConfigDir: filepath.Join(root, ".config"), CommandRunner: runner, SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil }, RuntimeDirPath: func(int) string { return runtimeDir }})
	if err != nil {
		t.Fatal(err)
	}
	first := runtimeTestArtifact(false, nil)
	runner.failName = ""
	if err := applier.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, ".config", "sway", "config"))
	if err != nil {
		t.Fatal(err)
	}
	second := runtimeTestArtifact(false, nil)
	second.Sway.Text = strings.Replace(second.Sway.Text, "# test", "# changed", 1)
	second.ArtifactHash = RuntimeArtifactHash(second)
	runner.failName = "/usr/bin/swaymsg"
	if err := applier.Apply(context.Background(), second); err == nil {
		t.Fatal("reload failure unexpectedly succeeded")
	}
	restored, err := os.ReadFile(filepath.Join(root, ".config", "sway", "config"))
	if err != nil || string(restored) != string(original) {
		t.Fatalf("rollback content = %q, %v", restored, err)
	}
}

func TestSwayRuntimeApplierRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, ".config")
	if err := os.Symlink(target, config); err != nil {
		t.Fatal(err)
	}
	runtimeDir := runtimeDirForTest(t, root)
	applier, err := NewSwayRuntimeApplier(RuntimeApplierOptions{ConfigDir: config, CommandRunner: &runtimeCommandRecorder{}, SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil }, RuntimeDirPath: func(int) string { return runtimeDir }})
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), runtimeTestArtifact(false, nil)); err == nil {
		t.Fatal("symlink config parent was accepted")
	}
}

func TestSwayRuntimeApplierNOVAKeysPresenceIsFailClosedOnlyWhenEnabled(t *testing.T) {
	root := t.TempDir()
	runner := &runtimeCommandRecorder{}
	runtimeDir := runtimeDirForTest(t, root)
	applier, err := NewSwayRuntimeApplier(RuntimeApplierOptions{
		ConfigDir: filepath.Join(root, ".config"), CommandRunner: runner,
		SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil },
		NovaKeysBinary: filepath.Join(root, "missing-novakeys"),
		RuntimeDirPath: func(int) string { return runtimeDir },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), runtimeTestArtifact(false, nil)); err != nil {
		t.Fatalf("disabled NOVA Keys should not require the binary: %v", err)
	}
	if err := applier.Apply(context.Background(), runtimeTestArtifact(true, nil)); err == nil || !strings.Contains(err.Error(), "NOVA Keys executable") {
		t.Fatalf("enabled NOVA Keys missing binary error = %v", err)
	}
}

func TestRuntimeArtifactHashMatchesCanonicalUnicodeFixture(t *testing.T) {
	artifact := RuntimeArtifact{
		Version: ProtocolVersion, Type: "runtime.config", Status: "ready", ArtifactRevision: "0-test",
		Sway:     &RuntimeComponent{Revision: 0, SourceRevision: 0, Source: "global", Mode: "raw", Text: "é \" quote " + "\u2028" + " " + "\u2029" + " " + "\\"},
		NOVAKeys: &RuntimeComponent{Revision: 0, SourceRevision: 0, Source: "global", Mode: "simple", Text: "日本語"},
		Layouts:  []RuntimeLayout{{LanguageCode: "en", TOML: "x=\"q\""}},
	}
	if got := RuntimeArtifactHash(artifact); got != "22e82239ab069fee57eb98d9fc60968399c1aaa9263e2eff524ed63b52099df7" {
		t.Fatalf("artifact hash = %s", got)
	}
	artifact.ArtifactHash = RuntimeArtifactHash(artifact)
	if err := ValidateRuntimeArtifact(artifact); err != nil {
		t.Fatalf("revision-0 artifact validation failed: %v", err)
	}
}

func TestLimitedRuntimeCommandOutputWriterBoundsWithoutShortWrite(t *testing.T) {
	var buffer bytes.Buffer
	writer := &limitedRuntimeWriter{writer: &buffer, limit: 4}
	input := []byte("secret output that must not leak")
	count, err := writer.Write(input)
	if err != nil || count != len(input) || !writer.exceeded {
		t.Fatalf("bounded writer result count=%d err=%v exceeded=%t", count, err, writer.exceeded)
	}
	if buffer.String() != "secr" {
		t.Fatalf("bounded output leaked or was not truncated: %q", buffer.String())
	}
}

func TestRuntimeOutputLimitAllowsExactBound(t *testing.T) {
	var buffer bytes.Buffer
	writer := &limitedRuntimeWriter{writer: &buffer, limit: 4}
	if n, err := writer.Write([]byte("1234")); err != nil || n != 4 || writer.exceeded {
		t.Fatalf("exact-bound output rejected: n=%d err=%v exceeded=%v", n, err, writer.exceeded)
	}
	if n, err := writer.Write([]byte("5")); err != nil || n != 1 || !writer.exceeded || buffer.String() != "1234" {
		t.Fatalf("overflow was not bounded: n=%d err=%v data=%q", n, err, buffer.String())
	}
}

func TestRuntimeManifestRejectsTrailingData(t *testing.T) {
	for _, suffix := range []string{"{}", " garbage"} {
		if _, err := decodeRuntimeManifest([]byte(`{"version":1,"layouts":[]}` + suffix)); err == nil {
			t.Fatalf("manifest accepted trailing data %q", suffix)
		}
	}
}

func TestSanitizeRuntimeDiagnosticEscapesControlsAndBoundsOutput(t *testing.T) {
	got := sanitizeRuntimeDiagnostic([]byte("line\nreturn\rtab\tzero\x00bell\x07"))
	if got != `line\nreturn\rtab\tzero\x00bell\x07` {
		t.Fatalf("sanitized controls = %q", got)
	}
	validator := "Error on line 7 'exec_always --no-startup-id chromium --kiosk 'https://user:pass@example.test/path?secret=query'\x01': invalid command"
	redacted := sanitizeRuntimeDiagnostic([]byte(validator))
	for _, forbidden := range []string{"https://", "user:pass", "secret=query", "exec_always", "chromium", "\x01"} {
		if strings.Contains(redacted, forbidden) {
			t.Fatalf("validator secret %q survived: %q", forbidden, redacted)
		}
	}
	if !strings.Contains(redacted, "Error on line 7") || !strings.Contains(redacted, "invalid command") {
		t.Fatalf("useful validator context was lost: %q", redacted)
	}
	long := sanitizeRuntimeDiagnostic(bytes.Repeat([]byte("x"), runtimeDiagnosticLimit+32))
	if len(long) > runtimeDiagnosticLimit || !strings.HasSuffix(long, "…") {
		t.Fatalf("bounded diagnostic length/suffix = %d/%q", len(long), long[len(long)-8:])
	}
	for _, character := range long {
		if character < 0x20 || character == 0x7f {
			t.Fatalf("raw control escaped diagnostic: %q", long)
		}
	}
}

func TestExecRuntimeCommandRunnerWrapsSanitizedCommandOutput(t *testing.T) {
	_, err := (ExecRuntimeCommandRunner{}).Run(context.Background(), "/bin/sh", []string{"-c", "printf 'line\\n\\001'; exit 1"}, nil)
	if err == nil {
		t.Fatal("failed command unexpectedly succeeded")
	}
	var commandErr *runtimeCommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("command error type = %T, %v", err, err)
	}
	if commandErr.Diagnostic() != `line\n\x01` {
		t.Fatalf("command diagnostic = %q", commandErr.Diagnostic())
	}
	if strings.ContainsRune(commandErr.Error(), '\x01') {
		t.Fatalf("raw control leaked through command error: %q", commandErr.Error())
	}
}

type runtimeDirFileInfo struct {
	os.FileInfo
	sys any
}

func (info runtimeDirFileInfo) Sys() any { return info.sys }

func TestSwayRuntimeApplierValidatesCurrentUserRuntimeDirectory(t *testing.T) {
	root := t.TempDir()
	newApplier := func(path string, info func(string) (os.FileInfo, error)) error {
		_, err := NewSwayRuntimeApplier(RuntimeApplierOptions{
			ConfigDir: filepath.Join(root, "config"), RuntimeDirPath: func(int) string { return path }, RuntimeDirInfo: info,
		})
		return err
	}
	missing := filepath.Join(root, "missing")
	if err := newApplier(missing, nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing runtime directory error = %v", err)
	}
	if err := newApplier("relative", nil); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("relative runtime directory error = %v", err)
	}
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := newApplier(unsafe, nil); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("world-readable runtime directory error = %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := newApplier(symlink, nil); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("symlink runtime directory error = %v", err)
	}
	foreign := filepath.Join(root, "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	baseInfo, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	foreignUID := uint32(os.Getuid() + 1)
	if err := newApplier(foreign, func(string) (os.FileInfo, error) {
		return runtimeDirFileInfo{FileInfo: baseInfo, sys: &syscall.Stat_t{Uid: foreignUID}}, nil
	}); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("foreign-owner runtime directory error = %v", err)
	}
}

func TestRuntimeEnvironmentOverrideReplacesInheritedRuntimeDirectory(t *testing.T) {
	merged := mergeRuntimeEnvironment([]string{"PATH=/usr/bin", "XDG_RUNTIME_DIR=/wrong", "XDG_RUNTIME_DIR=/also-wrong"}, []string{"XDG_RUNTIME_DIR=/run/user/1234"})
	values := make([]string, 0, 1)
	for _, entry := range merged {
		if strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") {
			values = append(values, entry)
		}
	}
	if len(values) != 1 || values[0] != "XDG_RUNTIME_DIR=/run/user/1234" {
		t.Fatalf("merged runtime environment = %v", values)
	}
}

func TestSwayRuntimeApplierPropagatesValidatedRuntimeEnvironment(t *testing.T) {
	root := t.TempDir()
	runtimeDir := runtimeDirForTest(t, root)
	runner := &runtimeCommandRecorder{}
	applier, err := NewSwayRuntimeApplier(RuntimeApplierOptions{
		ConfigDir: filepath.Join(root, "config"), CommandRunner: runner, SwaySocket: "/tmp/test-sway.sock",
		ValidateSocket: func(string) error { return nil }, RuntimeDirPath: func(int) string { return runtimeDir },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), runtimeTestArtifact(false, nil)); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	calls := append([]runtimeCommandCall(nil), runner.calls...)
	runner.mu.Unlock()
	wantValidation := []string{
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"WLR_BACKENDS=headless",
		"WLR_RENDERER=pixman",
		"WLR_LIBINPUT_NO_DEVICES=1",
	}
	wantReload := []string{"XDG_RUNTIME_DIR=" + runtimeDir, "SWAYSOCK=/tmp/test-sway.sock"}
	validate, reload := false, false
	for _, call := range calls {
		if call.name == "/usr/bin/sway" && len(call.args) > 0 && call.args[0] == "--validate" {
			validate = slices.Equal(call.environment, wantValidation)
		}
		if call.name == "/usr/bin/swaymsg" {
			reload = slices.Equal(call.environment, wantReload)
		}
		if call.name != "/usr/bin/sway" && call.name != "/usr/bin/swaymsg" && len(call.environment) != 0 {
			t.Fatalf("headless validation environment leaked to %s: %v", call.name, call.environment)
		}
		if call.name == "/usr/bin/swaymsg" && (slices.Contains(call.environment, "WLR_BACKENDS=headless") || slices.Contains(call.environment, "WLR_RENDERER=pixman") || slices.Contains(call.environment, "WLR_LIBINPUT_NO_DEVICES=1")) {
			t.Fatalf("headless validation environment leaked to swaymsg: %v", call.environment)
		}
	}
	if !validate || !reload {
		t.Fatalf("validated runtime environment missing: %+v", calls)
	}
}

func TestRuntimeValidationEnvironmentReplacesInheritedHeadlessValues(t *testing.T) {
	root := t.TempDir()
	runtimeDir := runtimeDirForTest(t, root)
	applier := &SwayRuntimeApplier{runtimeDir: runtimeDir}
	base := []string{
		"PATH=/usr/bin",
		"XDG_RUNTIME_DIR=/wrong",
		"WLR_BACKENDS=wayland",
		"WLR_RENDERER=gles2",
		"WLR_LIBINPUT_NO_DEVICES=0",
	}
	merged := mergeRuntimeEnvironment(base, applier.runtimeValidationEnvironment())
	want := []string{
		"PATH=/usr/bin",
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"WLR_BACKENDS=headless",
		"WLR_RENDERER=pixman",
		"WLR_LIBINPUT_NO_DEVICES=1",
	}
	if !slices.Equal(merged, want) {
		t.Fatalf("merged validation environment = %v, want %v", merged, want)
	}
}

func TestSwayRuntimeApplierKeepsPreviousGenerationWhenValidationFails(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, ".config")
	runner := &runtimeCommandRecorder{}
	applier := runtimeTestApplier(t, configDir, runner, nil)
	first := runtimeTestArtifact(false, nil)
	if err := applier.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(configDir, "sway", "config"))
	if err != nil {
		t.Fatal(err)
	}
	runner.failName = "/usr/bin/sway"
	second := runtimeTestArtifact(false, nil)
	second.Sway.Text = strings.Replace(second.Sway.Text, "# test", "invalid sway command", 1)
	second.ArtifactHash = RuntimeArtifactHash(second)
	if err := applier.Apply(context.Background(), second); err == nil {
		t.Fatal("validation failure unexpectedly succeeded")
	}
	restored, err := os.ReadFile(filepath.Join(configDir, "sway", "config"))
	if err != nil || string(restored) != string(original) {
		t.Fatalf("previous generation after validation failure = %q, %v", restored, err)
	}
	if _, err := os.Stat(runtimeTransactionJournalPath(configDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validation failure left transaction journal: %v", err)
	}
}

type rollbackRecoveryRunner struct {
	configDir   string
	liveSway    string
	liveKeys    string
	cancel      context.CancelFunc
	cleanup     bool
	failReload  bool
	failKeys    bool
	failRestore bool
}

func (runner *rollbackRecoveryRunner) Run(ctx context.Context, name string, args, env []string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "/usr/bin/swaymsg" && len(args) == 1 && args[0] == "reload" {
		if runner.cleanup && runner.failReload {
			return nil, errors.New("restore reload failed")
		}
		data, err := os.ReadFile(filepath.Join(runner.configDir, "sway/config"))
		if err != nil {
			return nil, err
		}
		runner.liveSway = string(data)
		if runner.cancel != nil {
			runner.cancel()
			runner.cancel = nil
			runner.cleanup = true
			if runner.failRestore {
				path := filepath.Join(runner.configDir, "sway/config")
				if err := os.Remove(path); err != nil {
					return nil, err
				}
				if err := os.Mkdir(path, 0700); err != nil {
					return nil, err
				}
			}
		}
	}
	if len(args) == 2 && args[0] == "-m" {
		if runner.cleanup && runner.failKeys {
			return nil, errors.New("restore NOVA Keys failed")
		}
		data, err := os.ReadFile(filepath.Join(runner.configDir, "novakeys/config"))
		if err != nil {
			return nil, err
		}
		runner.liveKeys = string(data)
	}
	return nil, nil
}

func TestRuntimeRollbackRecoversActiveGenerationAfterCancellation(t *testing.T) {
	for _, failure := range []string{"none", "reload", "keys", "restore"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			runtimeDir := filepath.Join(dir, "runtime")
			if err := os.Mkdir(runtimeDir, 0700); err != nil {
				t.Fatal(err)
			}
			runner := &rollbackRecoveryRunner{configDir: dir}
			options := RuntimeApplierOptions{ConfigDir: dir, CommandRunner: runner, SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil }, RuntimeDirPath: func(int) string { return runtimeDir }, NovaKeysBinary: runtimeExecutable(t)}
			applier, err := NewSwayRuntimeApplier(options)
			if err != nil {
				t.Fatal(err)
			}
			old := runtimeTestArtifact(true, nil)
			if err := applier.Apply(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			next := runtimeTestArtifact(true, nil)
			next.Sway.Text += "# NEXT GENERATION\n"
			next.NOVAKeys.Text += "# NEXT GENERATION\n"
			next.ArtifactHash = RuntimeArtifactHash(next)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner.cancel, runner.failReload, runner.failKeys, runner.failRestore = cancel, failure == "reload", failure == "keys", failure == "restore"
			if err := applier.Apply(ctx, next); !errors.Is(err, context.Canceled) {
				t.Fatalf("original cancellation lost: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "sway/config"))
			if failure != "restore" && (err != nil || string(data) != old.Sway.Text) {
				t.Fatalf("old files not restored: %v", err)
			}
			_, journalErr := os.Stat(runtimeTransactionJournalPath(dir))
			if failure == "none" {
				if !os.IsNotExist(journalErr) || runner.liveSway != old.Sway.Text || runner.liveKeys != old.NOVAKeys.Text {
					t.Fatal("bounded rollback failed to restore active generation")
				}
			} else {
				if journalErr != nil {
					t.Fatalf("failed active recovery lost journal: %v", journalErr)
				}
				runner.failReload, runner.failKeys = false, false
				if failure == "restore" {
					if err := os.Remove(filepath.Join(dir, "sway/config")); err != nil {
						t.Fatal(err)
					}
				}
				fresh, err := NewSwayRuntimeApplier(options)
				if err != nil {
					t.Fatal(err)
				}
				if err := fresh.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(runtimeTransactionJournalPath(dir)); !os.IsNotExist(err) || runner.liveSway != old.Sway.Text || runner.liveKeys != old.NOVAKeys.Text {
					t.Fatal("fresh recovery did not restore old active generation")
				}
			}
		})
	}
}

func TestRuntimeRollbackAfterFinalCommitWriteFailure(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	runner := &rollbackRecoveryRunner{configDir: dir}
	journalPath := runtimeTransactionJournalPath(dir)
	savedJournal := filepath.Join(dir, "saved-reload-pending.json")
	armed, triggered := false, false
	options := RuntimeApplierOptions{ConfigDir: dir, CommandRunner: runner, SwaySocket: "/tmp/test-sway.sock", ValidateSocket: func(string) error { return nil }, RuntimeDirPath: func(int) string { return runtimeDir }, NovaKeysBinary: runtimeExecutable(t), TransactionHook: func(stage string) error {
		if !armed || stage != runtimeTransactionBeforeCommitStage {
			return nil
		}
		triggered = true
		// Preserve the durable reload-pending evidence while obstructing only
		// its replacement target. This produces a real commit-write failure
		// without depending on the test process's UID or a new production hook.
		if err := os.Rename(journalPath, savedJournal); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(journalPath, 0700); err != nil {
			t.Fatal(err)
		}
		return nil
	}}
	applier, err := NewSwayRuntimeApplier(options)
	if err != nil {
		t.Fatal(err)
	}
	old := runtimeTestArtifact(true, nil)
	if err := applier.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := runtimeTestArtifact(true, nil)
	next.Sway.Text += "# COMMIT FAILURE GENERATION\n"
	next.NOVAKeys.Text += "# COMMIT FAILURE GENERATION\n"
	next.ArtifactHash = RuntimeArtifactHash(next)
	armed = true
	err = applier.Apply(context.Background(), next)
	if !triggered || err == nil || !strings.Contains(err.Error(), "managed runtime path is unsafe") {
		t.Fatalf("commit-write cause lost: triggered=%v error=%v", triggered, err)
	}
	if runner.liveSway != old.Sway.Text || runner.liveKeys != old.NOVAKeys.Text {
		t.Fatal("commit-write failure left new active generation")
	}
	data, readErr := os.ReadFile(savedJournal)
	var journal runtimeTransactionJournal
	if readErr != nil || json.Unmarshal(data, &journal) != nil || journal.Phase != "reload-pending" {
		t.Fatalf("recovery evidence lost: %v", readErr)
	}
	if info, err := os.Stat(journalPath); err != nil || !info.IsDir() {
		t.Fatal("obstructed journal was incorrectly cleared")
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedJournal, journalPath); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewSwayRuntimeApplier(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) || runner.liveSway != old.Sway.Text || runner.liveKeys != old.NOVAKeys.Text {
		t.Fatal("fresh recovery did not finish old generation")
	}
}
