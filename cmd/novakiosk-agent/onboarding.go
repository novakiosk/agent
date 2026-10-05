package main

import (
	"fmt"
	"strings"

	"github.com/novakiosk/agent/enrollment"
)

func formatSmokeCompletion(executable, stateDir string, kind enrollment.DeviceKind) string {
	message := "Smoke complete after one heartbeat."
	if stateDir == "/var/lib/novakiosk-agentd" {
		message += "\nThe pre-enabled OS or Print Bridge authority service takes over automatically after this command exits."
		if enrollment.EffectiveDeviceKind(kind) == enrollment.DeviceKindKiosk {
			message += " The graphical companion connects when the kiosk session is ready."
		}
		return message + "\nFor a manual installation without a configured service, run as the same authority user: " + formatNextRunCommandForKind(executable, stateDir, kind)
	}
	if enrollment.EffectiveDeviceKind(kind) == enrollment.DeviceKindKiosk && stateDir == "/var/lib/novakiosk-agent" {
		message += "\nOn NOVA Kiosk OS, the pre-enabled kiosk service takes over automatically after enrollment when the graphical session is ready."
	}
	return message + "\nFor a manual installation without a configured service, run as the same user: " + formatNextRunCommandForKind(executable, stateDir, kind)
}

// formatNextRunCommandForKind renders a shell-safe handoff command.
func formatNextRunCommandForKind(executable, stateDir string, kind enrollment.DeviceKind) string {
	if !safeExecutableArg(executable) {
		executable = "novakiosk-agent"
	}
	command := "run --state-dir " + quoteShellArg(stateDir) + " --runtime-mode sway"
	if enrollment.EffectiveDeviceKind(kind) == enrollment.DeviceKindPrintServer {
		command = "print-bridge --state-dir " + quoteShellArg(stateDir)
	}
	if stateDir == "/var/lib/novakiosk-agentd" {
		command = "agentd --state-dir " + quoteShellArg(stateDir)
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
