package enrollment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedSwayStartupRecoversBeforeDesiredGates(t *testing.T) {
	for _, kind := range []string{"absent", "blocked", "already-acknowledged", "recovery-error"} {
		t.Run(kind, func(t *testing.T) {
			fixture, client, _ := newRunFixture(t, false, false)
			dir := filepath.Join(t.TempDir(), "config")
			runner := &runtimeCommandRecorder{}
			nova := runtimeExecutable(t)
			old := runtimeTestArtifact(true, nil)
			old.Sway.Text += "# old\n"
			old.ArtifactHash = RuntimeArtifactHash(old)
			next := runtimeTestArtifact(true, nil)
			next.Sway.Text += "# next\n"
			next.ArtifactHash = RuntimeArtifactHash(next)
			if err := runtimeTestApplierWithNova(t, dir, runner, nil, nova).Apply(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			hook := func(stage string) error {
				if stage == runtimeTransactionAfterReloadStage {
					return ErrRuntimeTransactionInterrupted
				}
				return nil
			}
			if err := runtimeTestApplierWithNova(t, dir, runner, hook, nova).Apply(context.Background(), next); !errors.Is(err, ErrRuntimeTransactionInterrupted) {
				t.Fatalf("interruption: %v", err)
			}
			fresh := runtimeTestApplierWithNova(t, dir, runner, nil, nova)
			if kind == "blocked" {
				blocked := next
				blocked.Status = "blocked"
				blocked.Sway = nil
				blocked.NOVAKeys = nil
				reason := "runtime-presentation-assignment-missing"
				blocked.BlockedReason = &reason
				blocked.ArtifactHash = RuntimeArtifactHash(blocked)
				fixture.runtime = &blocked
			}
			if kind == "already-acknowledged" {
				fixture.runtime = &old
				state := fixture.state
				state.LastRuntimeArtifactHash = old.ArtifactHash
				state.LastRuntimeArtifactRevision = old.ArtifactRevision
				state.LastRuntimeAckResult = "applied"
				state.LastRuntimeAckAccepted = true
				state.RuntimeAckSequence = 1
				state.LastRuntimeAckAt = "2026-08-24T12:00:00Z"
				if err := SaveStateAtomic(client.StateDir, state); err != nil {
					t.Fatal(err)
				}
			}
			runner.calls = nil
			if kind == "recovery-error" {
				runner.failName = "/usr/bin/swaymsg"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- client.Run(ctx, RunOptions{RuntimeMode: "sway", RuntimeApplier: fresh, HeartbeatInterval: time.Hour})
			}()
			if kind == "recovery-error" {
				select {
				case err := <-done:
					if err == nil || !strings.Contains(err.Error(), "recovery") {
						t.Fatalf("recovery error not propagated: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("startup continued despite recovery failure")
				}
				if fixture.handshakes.Load() != 0 {
					t.Fatal("network started before failed recovery")
				}
				return
			}
			select {
			case <-fixture.heartbeats:
			case err := <-done:
				t.Fatalf("run stopped: %v", err)
			case <-ctx.Done():
				t.Fatal("no heartbeat")
			}
			cancel()
			<-done
			data, err := os.ReadFile(filepath.Join(dir, "sway/config"))
			if err != nil || string(data) != old.Sway.Text {
				t.Fatalf("interrupted config not recovered before session: %q %v", data, err)
			}
			if _, err := os.Stat(runtimeTransactionJournalPath(dir)); !os.IsNotExist(err) {
				t.Fatalf("recovery journal retained: %v", err)
			}
			runner.mu.Lock()
			defer runner.mu.Unlock()
			reloaded, reconciled := false, false
			for _, call := range runner.calls {
				if call.name == "/usr/bin/swaymsg" && strings.Join(call.args, " ") == "reload" {
					reloaded = true
				}
				if call.name == nova && strings.Join(call.args, " ") == "-m reload-config" {
					reconciled = true
				}
			}
			if !reloaded || !reconciled {
				t.Fatalf("missing recovery side effects reload=%v novakeys=%v", reloaded, reconciled)
			}
		})
	}
}
