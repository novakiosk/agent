package enrollment

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startupManagedState() State {
	return State{Version: ProtocolVersion, Status: "Managed", InstanceURL: "https://control.example", EnrollmentID: "enrollment-1", DeviceID: "fixture-device", PublicIdentityRef: "fixture-identity", IdentityBindingID: "binding-1", SessionID: "session-1", HeartbeatSequence: 1, LastHeartbeatAt: "2026-08-24T12:00:00Z"}
}

func TestStartupWaitsForExplicitEnrollment(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := waitForKioskStartup(ctx, dir, "browser", time.Millisecond, func() (bool, error) {
			t.Error("browser mode must not require Sway")
			return false, nil
		})
		done <- err
	}()
	assertWaiting := func() {
		t.Helper()
		select {
		case err := <-done:
			t.Fatalf("startup returned before enrollment: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	assertWaiting()
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("unconfigured startup created local state: %v, %v", files, err)
	}
	state := startupManagedState()
	state.Status = "Pending"
	if err := SaveStateAtomic(dir, state); err != nil {
		t.Fatal(err)
	}
	assertWaiting()
	state.Status = "Managed"
	if err := SaveStateAtomic(dir, state); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStartupCancellationAndInvalidState(t *testing.T) {
	for _, fixture := range []string{"unconfigured", "malformed", "insecure", "print-server", "mode"} {
		t.Run(fixture, func(t *testing.T) {
			dir := t.TempDir()
			mode := "sway"
			switch fixture {
			case "malformed":
				if err := os.WriteFile(StatePath(dir), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "insecure":
				if err := SaveStateAtomic(dir, startupManagedState()); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(StatePath(dir), 0644); err != nil {
					t.Fatal(err)
				}
			case "print-server":
				state := startupManagedState()
				state.DeviceKind = DeviceKindPrintServer
				if err := SaveStateAtomic(dir, state); err != nil {
					t.Fatal(err)
				}
			case "mode":
				mode = "invalid"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			_, err := waitForKioskStartup(ctx, dir, mode, time.Millisecond, func() (bool, error) { t.Error("unexpected graphics check"); return false, nil })
			if fixture == "unconfigured" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error = %v", err)
				}
			} else if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected actionable startup error, got %v", err)
			}
		})
	}
}

func TestStartupReloadsStateWhileAwaitingSway(t *testing.T) {
	dir := t.TempDir()
	if err := SaveStateAtomic(dir, startupManagedState()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	calls := 0
	_, err := waitForKioskStartup(ctx, dir, "sway", time.Millisecond, func() (bool, error) {
		calls++
		if err := os.Remove(StatePath(dir)); err != nil {
			t.Fatal(err)
		}
		return false, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("error %v, graphics calls %d", err, calls)
	}
}

func TestStartupGraphicalSocketsAppearAndRejectUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("SWAYSOCK", filepath.Join(dir, "sway.sock"))
	check := func(wantReady, wantError bool) {
		t.Helper()
		ready, err := kioskGraphicalSessionReady()
		if ready != wantReady || (err != nil) != wantError {
			t.Fatalf("ready=%v error=%v", ready, err)
		}
	}
	check(false, false)
	if err := os.WriteFile(filepath.Join(dir, "wayland-0.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	check(false, false)
	wayland, err := net.Listen("unix", filepath.Join(dir, "wayland-0"))
	if err != nil {
		t.Fatal(err)
	}
	defer wayland.Close()
	check(false, false)
	sway, err := net.Listen("unix", filepath.Join(dir, "sway.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer sway.Close()
	check(true, false)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	check(false, true)
}

func TestStartupRejectsInvalidGraphicalEnvironment(t *testing.T) {
	for _, variable := range []string{"XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "SWAYSOCK"} {
		t.Run(variable, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XDG_RUNTIME_DIR", dir)
			t.Setenv("WAYLAND_DISPLAY", "wayland-0")
			t.Setenv("SWAYSOCK", filepath.Join(dir, "missing-sway.sock"))
			listener, err := net.Listen("unix", filepath.Join(dir, "wayland-0"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			t.Setenv(variable, "relative")
			if ready, err := kioskGraphicalSessionReady(); ready || err == nil {
				t.Fatalf("invalid %s: ready=%v err=%v", variable, ready, err)
			}
		})
	}
}
