package main

import (
	"fmt"
	"strings"

	"github.com/novakiosk/agent/enrollment"
)

// formatNextRunCommandForKind renders a shell-safe handoff command.
func formatNextRunCommandForKind(executable, stateDir string, kind enrollment.DeviceKind) string {
	if !safeExecutableArg(executable) {
		executable = "novakiosk-agent"
	}
	command := "run --state-dir " + quoteShellArg(stateDir) + " --runtime-mode sway"
	if enrollment.EffectiveDeviceKind(kind) == enrollment.DeviceKindPrintServer {
		command = "print-bridge --state-dir " + quoteShellArg(stateDir)
	}
	return fmt.Sprintf("%s %s", executable, command)
}

func safeExecutableArg(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("/._-", character)) {
			return false
		}
	}
	return true
}

func quoteShellArg(value string) string {
	if value != "" && safeExecutableArg(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
