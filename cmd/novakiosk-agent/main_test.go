package main

import (
	"os/exec"
	"strings"
	"testing"

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
