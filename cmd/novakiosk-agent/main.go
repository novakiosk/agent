package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/novakiosk/agent/cupsjob"
	"github.com/novakiosk/agent/cupsreconcile"
	"github.com/novakiosk/agent/enrollment"
	"github.com/novakiosk/agent/printer"
)

// version is set by the release build; ordinary go builds remain identifiable.
var version = "development"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		fmt.Printf("novakiosk-agent %s\n", version)
	case "status":
		status(os.Args[2:])
	case "enroll":
		enroll(os.Args[2:])
	case "smoke":
		smoke(os.Args[2:])
	case "run":
		run(os.Args[2:])
	case "print-bridge":
		printBridge(os.Args[2:])
	case "cups-helper":
		cupsHelper(os.Args[2:])
	case "cups-job-helper":
		cupsJobHelper(os.Args[2:])
	case "doctor":
		doctor(os.Args[2:])
	case "printer-probe":
		printerProbe(os.Args[2:])
	case "idle-surface":
		idleSurface(os.Args[2:])
	case "reset":
		reset(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: novakiosk-agent version | status --state-dir DIR | enroll --instance HTTPS_URL --state-dir DIR [--scope SCOPE] [--device-kind kiosk|print-server] [--provisional [--device-id EXPECTED_ID] | --device-id ID --identity-ref REF --proof-kind KIND --proof-file PATH] | smoke --instance HTTPS_URL --state-dir DIR [--scope SCOPE] [--device-kind kiosk|print-server] [--device-id EXPECTED_ID] | run --state-dir DIR [--instance HTTPS_URL] [--ca PEM_PATH] [--heartbeat-interval DURATION] [--runtime-mode browser|sway] [--browser-user-data-dir DIR] [--chromium PATH] | print-bridge --state-dir DIR [--instance HTTPS_URL] [--ca PEM_PATH] [--heartbeat-interval DURATION] | cups-job-helper --profile kiosk|print-bridge | doctor [--runtime-mode browser|sway] [--chromium PATH] | printer-probe [--wait DURATION] | idle-surface --state-dir DIR [--chromium PATH] | reset --state-dir DIR [--yes]")
}

func idleSurface(args []string) {
	flags := flag.NewFlagSet("idle-surface", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	chromium := flags.String("chromium", "", "Chromium binary path")
	if err := flags.Parse(args); err != nil || strings.TrimSpace(*stateDir) == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "idle-surface requires only --state-dir DIR and optional --chromium PATH")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := enrollment.RunIdleSurface(ctx, enrollment.IdleSurfaceOptions{StateDir: *stateDir, ChromiumBinary: *chromium}); err != nil {
		// Do not print Chromium, document, or profile details: this helper is
		// launched by swayidle and diagnostics must remain bounded/local.
		fmt.Fprintln(os.Stderr, "idle-surface failed")
		os.Exit(1)
	}
}

func cupsHelper(args []string) {
	flags := flag.NewFlagSet("cups-helper", flag.ExitOnError)
	profile := flags.String("profile", "", "fixed helper profile: kiosk or print-bridge")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "cups-helper requires root through its fixed systemd unit")
		os.Exit(1)
	}
	stateDir, manifestDir, ok := cupsreconcile.ProfilePaths(*profile)
	if !ok {
		fmt.Fprintln(os.Stderr, "cups-helper profile is invalid")
		os.Exit(2)
	}
	if err := cupsreconcile.ApplyHelper(context.Background(), cupsreconcile.HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: *profile}); err != nil {
		fmt.Fprintln(os.Stderr, "cups-helper failed")
		os.Exit(1)
	}
}

func cupsJobHelper(args []string) {
	flags := flag.NewFlagSet("cups-job-helper", flag.ExitOnError)
	profile := flags.String("profile", "", "fixed helper profile: kiosk or print-bridge")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "cups-job-helper requires root through its fixed systemd unit")
		os.Exit(1)
	}
	stateDir, manifestDir, ok := cupsjob.ProfilePaths(*profile)
	if !ok {
		fmt.Fprintln(os.Stderr, "cups-job-helper profile is invalid")
		os.Exit(2)
	}
	if err := cupsjob.ApplyHelper(context.Background(), cupsjob.HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: *profile}); err != nil {
		fmt.Fprintln(os.Stderr, "cups-job-helper failed")
		os.Exit(1)
	}
}

func run(args []string) {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	instance := flags.String("instance", "", "optional HTTPS origin consistency check")
	caPath := flags.String("ca", "", "explicit trusted CA PEM path")
	heartbeatInterval := flags.Duration("heartbeat-interval", 15*time.Second, "managed desired-state heartbeat interval")
	userDataDir := flags.String("browser-user-data-dir", "", "persistent Chromium user-data directory")
	chromium := flags.String("chromium", "", "Chromium binary path")
	runtimeMode := flags.String("runtime-mode", "browser", "runtime mode: browser or sway")
	runtimeConfigDir := flags.String("runtime-config-dir", "", "optional XDG config directory override for Sway runtime")
	_ = flags.Parse(args)
	if strings.TrimSpace(*stateDir) == "" || *heartbeatInterval <= 0 || *heartbeatInterval > 24*time.Hour || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "state-dir and a bounded positive heartbeat interval are required")
		os.Exit(2)
	}
	if *instance != "" {
		if _, err := enrollment.CanonicalInstanceURL(*instance); err != nil {
			fmt.Fprintln(os.Stderr, "instance must be an HTTPS origin")
			os.Exit(2)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	state, err := enrollment.WaitForKioskStartup(ctx, *stateDir, *runtimeMode)
	if errors.Is(err, context.Canceled) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "kiosk startup failed: %v\n", err)
		os.Exit(1)
	}
	if *instance != "" {
		canonical, canonicalErr := enrollment.CanonicalInstanceURL(*instance)
		if canonicalErr != nil || canonical != state.InstanceURL {
			fmt.Fprintln(os.Stderr, "instance does not match managed state")
			os.Exit(2)
		}
	}
	client := enrollment.Client{StateDir: *stateDir, CAPath: *caPath, PrinterReconcileSupported: true, PrinterStatisticsSupported: true, PrinterJobsSupported: true, PrinterJobCancelSupported: true, PrinterQueueControlSupported: true, IdleScreenSupported: true, RemoteDesktopSupported: true, BrowserSupported: true, IdleDiagnostics: func(event enrollment.IdleDiagnostic) {
		fmt.Fprintf(os.Stderr, "idle runtime apply failed (%s, %s)\n", event.ErrorCategory, event.Stage)
	}}
	var runtimeApplier enrollment.RuntimeApplier
	if *runtimeMode == "sway" {
		applier, applierErr := enrollment.NewSwayRuntimeApplier(enrollment.RuntimeApplierOptions{ConfigDir: *runtimeConfigDir})
		if applierErr != nil {
			fmt.Fprintf(os.Stderr, "Sway runtime setup failed: %v\n", applierErr)
			os.Exit(1)
		}
		runtimeApplier = applier
	}
	remoteDesktopManager, managerErr := enrollment.NewRemoteDesktopManager(enrollment.RemoteDesktopManagerOptions{StateDir: *stateDir, InstanceURL: state.InstanceURL, CAPath: *caPath})
	if managerErr != nil {
		fmt.Fprintln(os.Stderr, "remote desktop setup failed")
		os.Exit(1)
	}
	agentBinary, _ := os.Executable()
	err = client.Run(ctx, enrollment.RunOptions{
		HeartbeatInterval: *heartbeatInterval,
		RuntimeMode:       *runtimeMode,
		RuntimeApplier:    runtimeApplier,
		RuntimeDiagnostics: func(event enrollment.RuntimeDiagnostic) {
			if event.Recovered {
				fmt.Fprintf(os.Stderr, "runtime configuration recovered after local apply failure (artifact %s)\n", event.ArtifactRevision)
				return
			}
			fmt.Fprintf(os.Stderr, "runtime configuration apply failed (artifact %s, %s): %s\n", event.ArtifactRevision, event.ErrorCategory, event.Detail)
		},
		PrinterReporter:           printer.NewProbe(printer.Config{OptionsPath: "/usr/bin/lpoptions", USBSysfsRoot: "/sys/bus/usb/devices"}),
		PrinterStatisticsReporter: printer.NewStatisticsProbe(printer.StatisticsConfig{}),
		PrinterJobsReporter:       printer.NewJobsProbe(printer.JobsConfig{}),
		PrinterJobCanceler:        cupsjob.CancelClient{StateDir: *stateDir, Profile: "kiosk"},
		PrinterQueueController:    cupsjob.CancelClient{StateDir: *stateDir, Profile: "kiosk"},
		PrinterReconciler:         cupsreconcile.Reconciler{StateDir: *stateDir, Profile: "kiosk"},
		BrowserUserDataDir:        *userDataDir,
		ChromiumBinary:            *chromium,
		AgentBinary:               agentBinary,
		RemoteDesktop:             remoteDesktopManager,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "managed run stopped: %v\n", err)
		os.Exit(1)
	}
}

func printBridge(args []string) {
	flags := flag.NewFlagSet("print-bridge", flag.ExitOnError)
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	instance := flags.String("instance", "", "optional HTTPS origin consistency check")
	caPath := flags.String("ca", "", "explicit trusted CA PEM path")
	heartbeatInterval := flags.Duration("heartbeat-interval", 15*time.Second, "managed printer-report heartbeat interval")
	reconnectDelay := flags.Duration("reconnect-delay", time.Second, "bounded reconnect delay")
	_ = flags.Parse(args)
	if strings.TrimSpace(*stateDir) == "" || *heartbeatInterval <= 0 || *heartbeatInterval > 24*time.Hour {
		fmt.Fprintln(os.Stderr, "state-dir and a bounded positive heartbeat interval are required")
		os.Exit(2)
	}
	state, err := enrollment.LoadState(*stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "managed state could not be read: %v\n", err)
		os.Exit(1)
	}
	if state.Status != "Managed" || enrollment.EffectiveDeviceKind(state.DeviceKind) != enrollment.DeviceKindPrintServer {
		fmt.Fprintln(os.Stderr, "print-bridge requires managed print-server state; kiosk state must use novakiosk-agent run")
		os.Exit(1)
	}
	if *instance != "" {
		canonical, canonicalErr := enrollment.CanonicalInstanceURL(*instance)
		if canonicalErr != nil || canonical != state.InstanceURL {
			fmt.Fprintln(os.Stderr, "instance does not match managed state")
			os.Exit(2)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = (enrollment.Client{StateDir: *stateDir, CAPath: *caPath, PrinterReconcileSupported: true, PrinterStatisticsSupported: true, PrinterJobsSupported: true, PrinterJobCancelSupported: true, PrinterQueueControlSupported: true}).PrintBridge(ctx, enrollment.PrintBridgeOptions{
		HeartbeatInterval:         *heartbeatInterval,
		ReconnectDelay:            *reconnectDelay,
		PrinterReporter:           printer.NewProbe(printer.Config{OptionsPath: "/usr/bin/lpoptions"}),
		PrinterStatisticsReporter: printer.NewStatisticsProbe(printer.StatisticsConfig{}),
		PrinterJobsReporter:       printer.NewJobsProbe(printer.JobsConfig{}),
		PrinterJobCanceler:        cupsjob.CancelClient{StateDir: *stateDir, Profile: "print-bridge"},
		PrinterQueueController:    cupsjob.CancelClient{StateDir: *stateDir, Profile: "print-bridge"},
		PrinterReconciler:         cupsreconcile.Reconciler{StateDir: *stateDir, Profile: "print-bridge"},
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "print bridge stopped: %v\n", err)
		os.Exit(1)
	}
}

func reset(args []string) {
	flags := flag.NewFlagSet("reset", flag.ExitOnError)
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	yes := flags.Bool("yes", false, "skip the interactive RESET confirmation")
	_ = flags.Parse(args)
	if strings.TrimSpace(*stateDir) == "" {
		fmt.Fprintln(os.Stderr, "state directory is required")
		os.Exit(2)
	}
	identity, err := enrollment.LoadIdentityForReset(*stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset could not inspect the local identity: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Device ID: %s\n", identity.DeviceID)
	fmt.Println("WARNING: this clears local enrollment state and preserves the device identity and key.")
	if !*yes {
		fmt.Print("Type RESET to continue: ")
		line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
		if readErr != nil && len(line) == 0 {
			fmt.Fprintln(os.Stderr, "reset confirmation was not accepted")
			os.Exit(1)
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line != "RESET" {
			fmt.Fprintln(os.Stderr, "reset confirmation was not accepted; enter RESET exactly")
			os.Exit(1)
		}
	}
	if err := enrollment.Reset(*stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "reset failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Reset complete for device %s. Identity preserved. Create a new enrollment code, then run novakiosk-agent smoke again.\n", identity.DeviceID)
}

func promptEnrollmentCode() (string, error) {
	return enrollment.ReadEnrollmentCode(os.Stdin, os.Stdout)
}

func validateExpectedDeviceID(expected, actual string) error {
	if expected == "" {
		return nil
	}
	if err := enrollment.ValidateDeviceID(expected); err != nil {
		return fmt.Errorf("expected device ID is invalid: %w", err)
	}
	if expected != actual {
		return fmt.Errorf("expected device ID %q does not match the local device identity", expected)
	}
	return nil
}

func validateScope(scope string) error {
	if err := enrollment.ValidateScope(scope); err != nil {
		return fmt.Errorf("invalid enrollment scope: %w", err)
	}
	return nil
}

func localHostname() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" || len(hostname) > 255 || strings.TrimSpace(hostname) != hostname {
		return "unknown"
	}
	for _, character := range hostname {
		if character < 0x21 || character == 0x7f {
			return "unknown"
		}
	}
	return hostname
}

func enrollmentCapabilities(kind enrollment.DeviceKind) []string {
	if enrollment.EffectiveDeviceKind(kind) == enrollment.DeviceKindPrintServer {
		return []string{"central-print-bridge", enrollment.PrinterStatisticsCapability, enrollment.PrinterJobsCapability, enrollment.PrinterJobCommandCapability}
	}
	return []string{"display", enrollment.PrinterStatisticsCapability, enrollment.PrinterJobsCapability, enrollment.PrinterJobCommandCapability}
}

func status(args []string) {
	flags := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	_ = flags.Parse(args)
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "state directory is required")
		os.Exit(2)
	}
	state, stateValue, err := enrollment.Status(*stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "status failed: %v\n", err)
		os.Exit(1)
	}
	if state == "Pending" || state == "Managed" {
		fmt.Printf("%s (device %s)\n", state, stateValue.DeviceID)
		return
	}
	fmt.Println(state)
}

func enroll(args []string) {
	flags := flag.NewFlagSet("enroll", flag.ExitOnError)
	instance := flags.String("instance", "", "HTTPS control-plane instance URL")
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	scope := flags.String("scope", "default", "exact enrollment scope")
	deviceID := flags.String("device-id", "", "device ID for opaque enrollment, or optional expected generated ID with --provisional")
	deviceKind := flags.String("device-kind", string(enrollment.DeviceKindKiosk), "device kind: kiosk or print-server")
	identityRef := flags.String("identity-ref", "", "public identity reference")
	proofKind := flags.String("proof-kind", "", "opaque proof kind (required; no final algorithm implied)")
	proofFile := flags.String("proof-file", "", "file containing opaque bootstrap proof")
	provisional := flags.Bool("provisional", false, "use the gated provisional Ed25519 identity")
	caPath := flags.String("ca", "", "explicit trusted CA PEM path")
	idempotencyKey := flags.String("idempotency-key", "", "enrollment idempotency key (generated and persisted when omitted)")
	_ = flags.Parse(args)
	if *instance == "" || *stateDir == "" {
		fmt.Fprintln(os.Stderr, "instance and state-dir are required")
		os.Exit(2)
	}
	if err := validateScope(*scope); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := enrollment.ValidateDeviceKind(enrollment.DeviceKind(*deviceKind)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_, attemptErr := enrollment.LoadAttempt(*stateDir)
	hasAttempt := attemptErr == nil
	if attemptErr != nil && !errors.Is(attemptErr, enrollment.ErrUnconfigured) {
		fmt.Fprintf(os.Stderr, "pending enrollment attempt could not be read: %v\n", attemptErr)
		os.Exit(1)
	}
	_, stateErr := enrollment.LoadState(*stateDir)
	hasState := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, enrollment.ErrUnconfigured) {
		fmt.Fprintf(os.Stderr, "existing enrollment state could not be read: %v\n", stateErr)
		os.Exit(1)
	}
	var proofBytes []byte
	var identity *enrollment.Identity
	if *provisional {
		loaded, err := enrollment.LoadOrCreateIdentity(*stateDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "provisional identity setup failed: %v\n", err)
			os.Exit(1)
		}
		identity = &loaded
		if err := validateExpectedDeviceID(*deviceID, identity.DeviceID); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	enrollmentDeviceID := *deviceID
	if identity != nil {
		enrollmentDeviceID = identity.DeviceID
	}
	if !hasAttempt {
		if enrollmentDeviceID == "" || (!*provisional && (*identityRef == "" || *proofKind == "" || *proofFile == "")) {
			fmt.Fprintln(os.Stderr, "device ID, identity-ref, proof-kind, and proof-file are required for a new non-provisional enrollment")
			os.Exit(2)
		}
		if *provisional {
			// The provisional enrollment proof is generated from the local
			// identity and is never accepted from argv or a proof file.
			proofBytes = nil
		} else {
			proofHandle, err := os.Open(*proofFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "proof file could not be read")
				os.Exit(1)
			}
			proofBytes, err = io.ReadAll(io.LimitReader(proofHandle, 4097))
			_ = proofHandle.Close()
			if err != nil || len(proofBytes) == 0 || len(proofBytes) > 4096 {
				fmt.Fprintln(os.Stderr, "proof file is empty or too large")
				os.Exit(1)
			}
		}
	}
	var enrollmentCode string
	if !hasState {
		var promptErr error
		enrollmentCode, promptErr = promptEnrollmentCode()
		if promptErr != nil {
			fmt.Fprintf(os.Stderr, "enrollment code was not accepted: %v\n", promptErr)
			os.Exit(1)
		}
	}
	state, err := (enrollment.Client{StateDir: *stateDir, CAPath: *caPath}).Enroll(context.Background(), enrollment.EnrollOptions{
		InstanceURL:       *instance,
		DeviceID:          enrollmentDeviceID,
		PublicIdentityRef: *identityRef,
		ProofKind:         *proofKind,
		ProofValue:        string(proofBytes),
		Inventory: enrollment.Inventory{
			Hostname:     localHostname(),
			OSVersion:    "unknown",
			AgentVersion: version,
			Capabilities: enrollmentCapabilities(enrollment.DeviceKind(*deviceKind)),
		},
		RequestedScope: *scope,
		IdempotencyKey: *idempotencyKey,
		Identity:       identity,
		EnrollmentCode: enrollmentCode,
		DeviceKind:     enrollment.DeviceKind(*deviceKind),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "enrollment failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Pending enrollment %s for device %s; compare %s\n", state.EnrollmentID, state.DeviceID, state.ComparisonValue)
}

func smoke(args []string) {
	flags := flag.NewFlagSet("smoke", flag.ExitOnError)
	instance := flags.String("instance", "", "HTTPS control-plane instance URL")
	stateDir := flags.String("state-dir", "", "explicit agent state directory")
	scope := flags.String("scope", "default", "exact enrollment scope")
	deviceID := flags.String("device-id", "", "optional expected generated device ID (compatibility check)")
	deviceKind := flags.String("device-kind", string(enrollment.DeviceKindKiosk), "device kind: kiosk or print-server")
	caPath := flags.String("ca", "", "explicit trusted CA PEM path")
	waitFor := flags.Duration("wait", 30*time.Second, "bounded approval wait")
	sequence := flags.Uint64("heartbeat-sequence", 1, "first heartbeat sequence")
	_ = flags.Parse(args)
	if *instance == "" || *stateDir == "" || *waitFor < 0 || *waitFor > 5*time.Minute || *sequence == 0 {
		fmt.Fprintln(os.Stderr, "instance, state-dir, bounded wait, and positive heartbeat-sequence are required")
		os.Exit(2)
	}
	if err := validateScope(*scope); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := enrollment.ValidateDeviceKind(enrollment.DeviceKind(*deviceKind)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	canonicalInstance, err := enrollment.CanonicalInstanceURL(*instance)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instance must be a canonical HTTPS origin")
		os.Exit(2)
	}
	identity, err := enrollment.LoadOrCreateIdentity(*stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provisional identity setup failed: %v\n", err)
		os.Exit(1)
	}
	if err := validateExpectedDeviceID(*deviceID, identity.DeviceID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	enrollmentDeviceID := identity.DeviceID
	client := enrollment.Client{StateDir: *stateDir, CAPath: *caPath}
	state, stateErr := enrollment.LoadState(*stateDir)
	if stateErr != nil {
		if !errors.Is(stateErr, enrollment.ErrUnconfigured) {
			fmt.Fprintf(os.Stderr, "pending enrollment state could not be read: %v\n", stateErr)
			os.Exit(1)
		}
		enrollmentCode, promptErr := promptEnrollmentCode()
		if promptErr != nil {
			fmt.Fprintf(os.Stderr, "enrollment code was not accepted: %v\n", promptErr)
			os.Exit(1)
		}
		state, err = client.Enroll(context.Background(), enrollment.EnrollOptions{
			InstanceURL: *instance, DeviceID: enrollmentDeviceID, Inventory: enrollment.Inventory{
				Hostname: localHostname(), OSVersion: "unknown", AgentVersion: version, Capabilities: enrollmentCapabilities(enrollment.DeviceKind(*deviceKind)),
			}, RequestedScope: *scope, Identity: &identity,
			EnrollmentCode: enrollmentCode,
			DeviceKind:     enrollment.DeviceKind(*deviceKind),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "provisional enrollment failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Pending enrollment %s for device %s; compare %s\n", state.EnrollmentID, state.DeviceID, state.ComparisonValue)
	} else {
		if state.InstanceURL != canonicalInstance {
			fmt.Fprintln(os.Stderr, "existing enrollment state does not match instance")
			os.Exit(1)
		}
		if state.DeviceID != identity.DeviceID {
			fmt.Fprintln(os.Stderr, "existing enrollment state does not match local device identity")
			os.Exit(1)
		}
		if state.Status == "Managed" {
			if enrollment.EffectiveDeviceKind(state.DeviceKind) != enrollment.DeviceKind(*deviceKind) {
				fmt.Fprintln(os.Stderr, "existing managed state has a different device kind")
				os.Exit(1)
			}
			nextSequence := *sequence
			if nextSequence <= state.HeartbeatSequence {
				nextSequence = state.HeartbeatSequence + 1
			}
			sessionContext, sessionCancel := context.WithTimeout(context.Background(), 30*time.Second)
			evidence, sessionErr := client.ConnectAndHeartbeatWithRetry(sessionContext, state, identity, enrollment.SessionOptions{HeartbeatSequence: nextSequence}, 2)
			sessionCancel()
			if sessionErr != nil {
				fmt.Fprintf(os.Stderr, "managed session reconnect failed: %v\n", sessionErr)
				os.Exit(1)
			}
			state.SessionID = evidence.SessionID
			state.HeartbeatSequence = evidence.HeartbeatSequence
			state.LastHeartbeatAt = evidence.LastHeartbeatAt
			if err := enrollment.SaveStateAtomic(*stateDir, state); err != nil {
				fmt.Fprintln(os.Stderr, "managed session state could not be persisted")
				os.Exit(1)
			}
			fmt.Printf("Managed session heartbeat accepted for device %s\n", state.DeviceID)
			fmt.Println(formatSmokeCompletion(os.Args[0], *stateDir, state.DeviceKind))
			return
		}
	}
	deadline := time.Now().Add(*waitFor)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			fmt.Fprintln(os.Stderr, "approval remained pending")
			os.Exit(1)
		}
		claimTimeout := min(remaining, 20*time.Second)
		claimContext, cancel := context.WithTimeout(context.Background(), claimTimeout)
		claim, claimErr := client.Claim(claimContext, state, identity)
		cancel()
		if claimErr == nil && claim.Status == "approved" {
			sessionContext, sessionCancel := context.WithTimeout(context.Background(), 30*time.Second)
			evidence, sessionErr := client.ConnectAndHeartbeatWithRetry(sessionContext, state, identity, enrollment.SessionOptions{HeartbeatSequence: *sequence}, 2)
			sessionCancel()
			if sessionErr != nil {
				fmt.Fprintf(os.Stderr, "managed session smoke failed: %v\n", sessionErr)
				os.Exit(1)
			}
			managed := state
			managed.Status = "Managed"
			managed.PublicIdentityRef = identity.PublicIdentityRef
			managed.IdentityBindingID = *claim.IdentityBindingID
			managed.SessionID = evidence.SessionID
			managed.HeartbeatSequence = evidence.HeartbeatSequence
			managed.LastHeartbeatAt = evidence.LastHeartbeatAt
			managed.DeviceKind = enrollment.EffectiveDeviceKind(state.DeviceKind)
			if err := enrollment.SaveStateAtomic(*stateDir, managed); err != nil {
				fmt.Fprintln(os.Stderr, "managed session state could not be persisted")
				os.Exit(1)
			}
			fmt.Printf("Managed session heartbeat accepted for device %s\n", managed.DeviceID)
			fmt.Println(formatSmokeCompletion(os.Args[0], *stateDir, managed.DeviceKind))
			return
		}
		if time.Now().After(deadline) {
			if claimErr != nil {
				fmt.Fprintf(os.Stderr, "approval claim failed or remained pending: %v\n", claimErr)
			} else {
				fmt.Fprintln(os.Stderr, "approval remained pending")
			}
			os.Exit(1)
		}
		time.Sleep(time.Second)
	}
}
