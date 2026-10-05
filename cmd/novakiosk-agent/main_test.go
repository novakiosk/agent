package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/novakiosk/agent/enrollment"
)

func TestShellHandoffPreservesLiteralArguments(t *testing.T) {
	for _, value := range []string{"#state", "~/state", "STATE=dir", "a b", "a'b", "$(false)", "", "/var/lib/agent"} {
		output, err := exec.Command("/bin/sh", "-c", "printf '%s' "+quoteShellArg(value)).Output()
		if err != nil || string(output) != value {
			t.Fatalf("argument %q became %q: %v", value, output, err)
		}
	}
	for _, executable := range []string{"#agent", "~/agent", "AGENT=agent"} {
		if safeExecutableArg(executable) {
			t.Fatalf("shell syntax accepted as executable: %q", executable)
		}
	}
}

func TestValidateExpectedDeviceID(t *testing.T) {
	if err := validateExpectedDeviceID("", "generated-device"); err != nil {
		t.Fatal(err)
	}
	if err := validateExpectedDeviceID("generated-device", "generated-device"); err != nil {
		t.Fatal(err)
	}
	if err := validateExpectedDeviceID("wrong-device", "generated-device"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want expected device mismatch", err)
	}
	if err := validateExpectedDeviceID("bad device", "generated-device"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error = %v, want invalid expected device ID", err)
	}
}

func TestValidateScope(t *testing.T) {
	for _, scope := range []string{"default", "site:fixture", "ops.eu-west_1"} {
		if err := validateScope(scope); err != nil {
			t.Fatalf("scope %q rejected: %v", scope, err)
		}
	}
	for _, scope := range []string{"", "site fixture", "site/fixture"} {
		if err := validateScope(scope); err == nil {
			t.Fatalf("scope %q unexpectedly accepted", scope)
		}
	}
}

func TestFormatNextRunCommandUsesExecutableAndExactStateDir(t *testing.T) {
	got := formatNextRunCommandForKind("/usr/bin/novakiosk-agent", "/var/lib/novakiosk-agent", enrollment.DeviceKindKiosk)
	want := "/usr/bin/novakiosk-agent run --state-dir /var/lib/novakiosk-agent --runtime-mode sway"
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestFormatNextRunCommandUsesPrintBridgeForPrintServer(t *testing.T) {
	got := formatNextRunCommandForKind("/usr/bin/novakiosk-agent", "/var/lib/novakiosk-agent", enrollment.DeviceKindPrintServer)
	want := "/usr/bin/novakiosk-agent print-bridge --state-dir /var/lib/novakiosk-agent"
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestFormatNextRunCommandRejectsUnsafeExecutable(t *testing.T) {
	got := formatNextRunCommandForKind("novakiosk-agent; touch /tmp/unexpected", "/var/lib/novakiosk-agent", enrollment.DeviceKindKiosk)
	want := "novakiosk-agent run --state-dir /var/lib/novakiosk-agent --runtime-mode sway"
	if got != want {
		t.Fatalf("command = %q, want safe fallback %q", got, want)
	}
}

func TestExplicitP256SoftwareSelection(t *testing.T) {
	for _, precreated := range []bool{false, true} {
		t.Run(fmt.Sprint(precreated), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "identity")
			if precreated {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			identity, err := loadSelectedIdentity(dir, "software")
			if err != nil {
				t.Fatal(err)
			}
			if identity.Profile() != enrollment.P256IdentityProfile {
				t.Fatal("wrong profile")
			}
			again, err := loadSelectedIdentity(dir, "software")
			if err != nil || again.PublicIdentityRef != identity.PublicIdentityRef {
				t.Fatal("key not preserved")
			}
			os.Remove(enrollment.IdentityPath(dir))
			os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{}`), 0600)
			if _, err := loadSelectedIdentity(dir, "software"); err == nil {
				t.Fatal("repaired incomplete authority state")
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "legacy")
	legacy, err := loadSelectedIdentity(dir, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSelectedIdentity(dir, "software"); err == nil {
		t.Fatal("silently replaced legacy identity")
	}
	loaded, err := enrollment.LoadIdentity(dir)
	if err != nil || loaded.PublicIdentityRef != legacy.PublicIdentityRef {
		t.Fatal("legacy identity changed")
	}
}

func TestP256EnrollCLIUsesGeneratedProof(t *testing.T) {
	if os.Getenv("NOVA_TEST_P256_ENROLL") == "1" {
		enroll([]string{"--instance", "https://control.example", "--state-dir", os.Getenv("NOVA_TEST_STATE"), "--identity-backing", "software"})
		return
	}
	dir := filepath.Join(t.TempDir(), "identity")
	command := exec.Command(os.Args[0], "-test.run=^TestP256EnrollCLIUsesGeneratedProof$")
	command.Env = append(os.Environ(), "NOVA_TEST_P256_ENROLL=1", "NOVA_TEST_STATE="+dir)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "enrollment code") || strings.Contains(string(output), "proof-file are required") {
		t.Fatalf("expected attended code prompt after P256 setup: %s (%v)", output, err)
	}
	identity, err := enrollment.LoadIdentity(dir)
	if err != nil || identity.Profile() != enrollment.P256IdentityProfile {
		t.Fatalf("P256 CLI identity missing: %v", err)
	}
}

func TestUnconfiguredDaemonIsInert(t *testing.T) {
	if os.Getenv("NOVA_TEST_AGENTD") == "1" {
		agentDaemon([]string{"--state-dir", os.Getenv("NOVA_TEST_STATE"), "--socket", os.Getenv("NOVA_TEST_SOCKET"), "--runtime-user", "nobody"})
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("production CLI intentionally rejects root")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "must-not-exist.sock")
	command := exec.Command(os.Args[0], "-test.run=^TestUnconfiguredDaemonIsInert$")
	command.Env = append(os.Environ(), "NOVA_TEST_AGENTD=1", "NOVA_TEST_STATE="+dir, "NOVA_TEST_SOCKET="+socket)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- command.Wait() }()
	select {
	case err := <-stopped:
		t.Fatalf("inert daemon exited: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		command.Process.Kill()
		t.Fatal("unconfigured daemon opened authority socket")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		command.Process.Kill()
		t.Fatal("unconfigured daemon mutated private state")
	}
	command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		command.Process.Kill()
		t.Fatal("daemon did not stop")
	}
}

func TestAuthoritySmokeCompletionUsesDaemonHandoff(t *testing.T) {
	for _, kind := range []enrollment.DeviceKind{enrollment.DeviceKindKiosk, enrollment.DeviceKindPrintServer} {
		text := formatSmokeCompletion("/usr/bin/novakiosk-agent", "/var/lib/novakiosk-agentd", kind)
		if !strings.Contains(text, "automatically") || !strings.Contains(text, "agentd --state-dir /var/lib/novakiosk-agentd") || strings.Contains(text, " run --") || strings.Contains(text, "systemctl enable") {
			t.Fatalf("wrong authority handoff: %s", text)
		}
		if kind == enrollment.DeviceKindPrintServer && strings.Contains(text, "graphical") {
			t.Fatal("print server completion requires graphical session")
		}
	}
}

func TestCapabilitiesCLI(t *testing.T) {
	if os.Getenv("NOVA_TEST_CAPABILITIES") == "1" {
		os.Args = []string{"novakiosk-agent", "capabilities"}
		main()
		os.Exit(0)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCapabilitiesCLI$")
	command.Env = append(os.Environ(), "NOVA_TEST_CAPABILITIES=1")
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "device-authority-v1 fleet-update-v1\n" {
		t.Fatalf("release capability guard would reject this Agent: %q %v", output, err)
	}
}
