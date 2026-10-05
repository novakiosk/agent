package enrollment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsreconcile"
	"github.com/novakiosk/agent/operations"
)

type RunOptions struct {
	FleetSystem               operations.FleetSystem
	HeartbeatInterval         time.Duration
	ReconnectDelay            time.Duration
	WriteTimeout              time.Duration
	RuntimeMode               string
	RuntimeApplier            RuntimeApplier
	IdleRuntime               IdleRuntime
	PrinterReporter           PrinterReporter
	PrinterStatisticsReporter PrinterStatisticsReporter
	PrinterJobsReporter       PrinterJobsReporter
	PrinterJobCanceler        PrinterJobCanceler
	PrinterQueueController    PrinterQueueController
	PrinterReconciler         cupsreconcile.Applier
	BrowserFactory            BrowserFactory
	ManagedBrowserFactory     func(context.Context, *RuntimeBrowserManagement) (Browser, error)
	RuntimeSnapshot           func(DesiredSnapshot)
	RuntimeEpoch              func() string
	BrowserUserDataDir        string
	ChromiumBinary            string
	AgentBinary               string
	InventoryCollector        *operations.InventoryCollector
	OperationExecutor         operations.CommandExecutor
	OperationClock            func() time.Time
	// DisplayModeObserver is an optional test seam. When nil, the client-level
	// observer is used, followed by the bounded system DRM observer.
	DisplayModeObserver func() DisplayMode
	RuntimeDiagnostics  func(RuntimeDiagnostic)
	RemoteDesktop       *RemoteDesktopManager
}

// RuntimeDiagnostic is local operator evidence. It is never included in the
// signed runtime ACK or sent to the control plane.
type RuntimeDiagnostic struct {
	ArtifactRevision string
	ErrorCategory    string
	Detail           string
	Recovered        bool
}

type runtimeDiagnosticReporter struct {
	sink        func(RuntimeDiagnostic)
	lastFailure string
}

func newRuntimeDiagnosticReporter(sink func(RuntimeDiagnostic)) *runtimeDiagnosticReporter {
	return &runtimeDiagnosticReporter{sink: sink}
}

func (reporter *runtimeDiagnosticReporter) failure(artifact RuntimeArtifact, category string, err error) {
	if reporter == nil {
		return
	}
	detail := runtimeDiagnosticText(err)
	key := strings.Join([]string{artifact.ArtifactRevision, artifact.ArtifactHash, category, detail}, "\x00")
	if key == reporter.lastFailure {
		return
	}
	reporter.lastFailure = key
	if reporter.sink != nil {
		reporter.sink(RuntimeDiagnostic{ArtifactRevision: runtimeDiagnosticRevision(artifact.ArtifactRevision), ErrorCategory: category, Detail: detail})
	}
}

func (reporter *runtimeDiagnosticReporter) applied(artifact RuntimeArtifact) {
	if reporter == nil || reporter.lastFailure == "" {
		return
	}
	if reporter.sink != nil {
		reporter.sink(RuntimeDiagnostic{ArtifactRevision: runtimeDiagnosticRevision(artifact.ArtifactRevision), Recovered: true})
	}
	reporter.lastFailure = ""
}

func runtimeDiagnosticRevision(revision string) string {
	if revision == "" {
		return "unknown"
	}
	return sanitizeRuntimeDiagnostic([]byte(revision))
}

func runtimeDiagnosticText(err error) string {
	if err == nil {
		return "runtime apply failed"
	}
	var detailed interface{ Diagnostic() string }
	if errors.As(err, &detailed) && detailed.Diagnostic() != "" {
		return sanitizeRuntimeDiagnostic([]byte(detailed.Diagnostic()))
	}
	detail := sanitizeRuntimeDiagnostic([]byte(err.Error()))
	if detail == "" {
		return "runtime apply failed"
	}
	return detail
}

func (options RunOptions) normalized() (RunOptions, error) {
	if options.RuntimeMode == "" {
		options.RuntimeMode = "browser"
	}
	if options.RuntimeMode != "browser" && options.RuntimeMode != "sway" {
		return RunOptions{}, fmt.Errorf("runtime mode must be browser or sway")
	}
	if options.HeartbeatInterval <= 0 {
		options.HeartbeatInterval = 15 * time.Second
	}
	if options.HeartbeatInterval > 24*time.Hour {
		return RunOptions{}, fmt.Errorf("heartbeat interval is out of bounds")
	}
	if options.ReconnectDelay <= 0 {
		options.ReconnectDelay = time.Second
	}
	if options.ReconnectDelay > 30*time.Second {
		return RunOptions{}, fmt.Errorf("reconnect delay is out of bounds")
	}
	if options.WriteTimeout <= 0 || options.WriteTimeout > 30*time.Second {
		options.WriteTimeout = sessionMessageTimeout
	}
	return options, nil
}

// managedChromiumOptions is shared by initial launch, commands, and recovery.
func managedChromiumOptions(binary, profile string, managed *RuntimeBrowserManagement) ChromiumOptions {
	options := ChromiumOptions{Binary: binary, UserDataDir: profile}
	if managed != nil {
		options.Kiosk = managed.Kiosk
		options.KioskPrinting = managed.KioskPrinting
		options.KioskConfigured = true
		options.RequireGraphicalSession = true
	}
	return options
}

// Run is the persistent managed-device loop. It has no reset or revocation
// recovery path: identity/session errors are returned to the supervisor while
// transport failures reconnect with bounded delay. Browser state is kept in a
// single Browser instance, so every revision uses the same top-level tab.
func (client Client) Run(ctx context.Context, options RunOptions) error {
	options, err := options.normalized()
	if err != nil {
		return err
	}
	if err := RequireOrdinaryAuthority(client.StateDir); err != nil {
		return err
	}
	state, err := LoadState(client.StateDir)
	if err != nil {
		return err
	}
	if state.Status != "Managed" {
		return fmt.Errorf("managed state is required")
	}
	if EffectiveDeviceKind(state.DeviceKind) != DeviceKindKiosk {
		return fmt.Errorf("run is kiosk-only; this managed state is a print server. Use novakiosk-agent print-bridge --state-dir %s", client.StateDir)
	}
	identity, err := LoadIdentity(client.StateDir)
	if err != nil {
		return err
	}
	defer identity.Close()
	if identity.DeviceID != state.DeviceID || state.PublicIdentityRef != identity.PublicIdentityRef {
		return fmt.Errorf("managed state identity does not match local identity")
	}
	var browser Browser
	defer func() {
		if browser != nil {
			_ = browser.Close()
		}
	}()
	var idleRuntime IdleRuntime
	var managedBrowserConfig *RuntimeBrowserManagement
	runtimeEpoch := ""
	browserUserDataDir := options.BrowserUserDataDir
	if browserUserDataDir == "" {
		browserUserDataDir = client.StateDir + "/browser"
	}
	browserFactory := func(ctx context.Context, userDataDir string) (Browser, error) {
		if options.ManagedBrowserFactory != nil {
			return options.ManagedBrowserFactory(ctx, managedBrowserConfig)
		}
		if options.BrowserFactory != nil {
			return options.BrowserFactory(ctx, userDataDir)
		}
		config := managedChromiumOptions(options.ChromiumBinary, userDataDir, managedBrowserConfig)
		return NewChromiumBrowser(ctx, config)
	}
	if options.RuntimeMode == "browser" {
		browser, err = browserFactory(ctx, browserUserDataDir)
		if err != nil {
			return fmt.Errorf("start browser: %w", err)
		}
	} else if options.RuntimeApplier == nil {
		options.RuntimeApplier, err = NewSwayRuntimeApplier(RuntimeApplierOptions{})
		if err != nil {
			return err
		}
	}
	if options.RuntimeMode == "sway" {
		if err := options.RuntimeApplier.Recover(ctx); err != nil {
			return fmt.Errorf("startup runtime recovery: %w", err)
		}
	}
	if client.IdleScreenSupported && options.IdleRuntime == nil {
		idleRuntime, err = NewSwayIdleRuntime(IdleRuntimeOptions{StateDir: client.StateDir, InstanceURL: state.InstanceURL, CAPath: client.CAPath, AgentBinary: options.AgentBinary, ChromiumBinary: options.ChromiumBinary})
		if err != nil {
			return err
		}
		options.IdleRuntime = idleRuntime
	} else {
		idleRuntime = options.IdleRuntime
	}
	if idleRuntime != nil {
		defer idleRuntime.Close()
	}
	if options.RemoteDesktop != nil {
		defer options.RemoteDesktop.Close()
	}
	runtimeReporter := newRuntimeDiagnosticReporter(options.RuntimeDiagnostics)
	printerReporter := options.PrinterReporter
	printerStatisticsReporter := options.PrinterStatisticsReporter
	printerJobsReporter := options.PrinterJobsReporter
	inventoryCollector := options.InventoryCollector
	if inventoryCollector == nil {
		inventoryCollector = operations.NewInventoryCollector()
	}
	operationExecutor := options.OperationExecutor
	if operationExecutor == nil {
		operationExecutor = operations.NewExecutor(operations.OperationConfig{Clock: options.OperationClock})
	}
	operationClock := options.OperationClock
	if operationClock == nil {
		operationClock = client.now
	}
	displayModeObserver := options.DisplayModeObserver
	if displayModeObserver == nil {
		displayModeObserver = client.DisplayModeObserver
	}
	if displayModeObserver == nil {
		displayModeObserver = ObserveDisplayMode
	}
	coordinator, err := operations.NewCoordinator(operations.CoordinatorConfig{
		StateDir: client.StateDir,
		Executor: operationExecutor,
		Clock:    operationClock,
	})
	if err != nil {
		return fmt.Errorf("operation state could not be opened")
	}

	var fleet *operations.FleetCoordinator
	fleetReports := &fleetReportCache{}
	if client.FleetUpdateSupported && EffectiveDeviceKind(state.DeviceKind) == DeviceKindKiosk {
		fleet, err = operations.NewFleetCoordinator(client.StateDir, options.FleetSystem, operationClock)
		if err != nil {
			return fmt.Errorf("fleet update state could not be opened: %w", err)
		}
		// The lifecycle belongs to the daemon, not a WebSocket connection. A lost
		// session does not cancel staging or defer the durable reboot transition.
		fleetCtx, cancelFleet := context.WithCancel(ctx)
		defer cancelFleet()
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-fleetCtx.Done():
					return
				case <-ticker.C:
					_ = fleet.Step(fleetCtx)
				}
			}
		}()
	}
	sequence := state.HeartbeatSequence
	// This marker is scoped to this Run/browser lifetime and survives WSS
	// reconnects, but is intentionally not restored from persisted state.
	browserAppliedRevisionID := ""
	playlistRevisionID := ""
	playlistIndex := 0
	playlistNextAt := time.Time{}
	browserRecoveryDue := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		connection, accepted, cleanup, connectErr := client.openManagedSession(ctx, state, identity, options.WriteTimeout)
		if connectErr != nil {
			if permanentSessionError(connectErr) {
				return connectErr
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(options.ReconnectDelay):
			}
			continue
		}
		sequence = state.HeartbeatSequence
		connectionErr := error(nil)
		ackedRevisionID := ""
		// Poll sequencing is scoped to this authenticated managed connection;
		// the server rejects replay/out-of-order polls independently of the
		// durable lifecycle ACK sequence.
		remotePollSequence := uint64(0)
		remotePollEnabled := false
		remotePollInterval := time.Duration(0)
		remotePollNextAt := time.Time{}
		nextHeartbeatAt := time.Time{}
		for {
			sequence++
			observedAt := client.now().UTC().Format(time.RFC3339Nano)
			displayMode := displayModeObserver()
			if !displayMode.Valid() {
				displayMode = DisplayModeUnknown
			}
			heartbeat := Heartbeat{
				Version: ProtocolVersion, Type: "session.heartbeat", Profile: identityProfile(state.PublicIdentityRef),
				SessionID: accepted.SessionID, DeviceID: state.DeviceID, Sequence: sequence, ObservedAt: observedAt, DisplayMode: displayMode,
			}
			var signErr error
			heartbeat.Signature, signErr = encodeIdentitySignature(identity, HeartbeatCanonical(heartbeat))
			if signErr != nil {
				connectionErr = signErr
				break
			}
			if err := writeSessionMessage(connection, heartbeat, options.WriteTimeout); err != nil {
				connectionErr = err
				break
			}
			var heartbeatAck heartbeatAccepted
			if err := readSessionMessage(ctx, connection, &heartbeatAck); err != nil {
				connectionErr = err
				break
			}
			if heartbeatAck.Version != ProtocolVersion || heartbeatAck.Type != "session.heartbeat.accepted" || heartbeatAck.SessionID != accepted.SessionID || heartbeatAck.Sequence != heartbeat.Sequence {
				connectionErr = fmt.Errorf("managed session heartbeat was not accepted")
				break
			}
			var snapshot DesiredSnapshot
			if err := readRuntimeSessionMessage(ctx, connection, &snapshot); err != nil {
				connectionErr = err
				break
			}
			replayBrowser := snapshot.BrowserCommand != nil && state.LastBrowserCommandID == snapshot.BrowserCommand.CommandID && state.LastBrowserCommandHash == snapshot.BrowserCommand.PayloadHash
			if err := validateDesiredSnapshotAt(snapshot, accepted.SessionID, state.DeviceID, client.now(), false, replayBrowser); err != nil {
				if snapshot.Operation == nil {
					connectionErr = err
					break
				}
				current, phase, present, currentErr := coordinator.CurrentCommand()
				if currentErr != nil || !present || current.CommandID != snapshot.Operation.CommandID || (phase != operations.PhaseAccepted && phase != operations.PhaseExecutionStarted && phase != operations.PhaseExecuted) {
					connectionErr = err
					break
				}
				if replayErr := validateDesiredSnapshotAt(snapshot, accepted.SessionID, state.DeviceID, client.now(), true, replayBrowser); replayErr != nil {
					connectionErr = replayErr
					break
				}
			}
			if options.RuntimeSnapshot != nil {
				options.RuntimeSnapshot(snapshot)
			}
			if options.RuntimeEpoch != nil {
				epoch := options.RuntimeEpoch()
				if epoch != runtimeEpoch {
					runtimeEpoch = epoch
					state.LastRuntimeArtifactHash = ""
					state.LastRuntimeAckAccepted = false
					state.LastIdleAckAccepted = false
				}
			}
			if client.PrinterReconcileSupported {
				if options.PrinterReconciler == nil {
					connectionErr = fmt.Errorf("printer reconciler is required")
					break
				}
				if err := client.receiveApplyAndAcknowledgePrinterDesired(ctx, &state, identity, connection, accepted.SessionID, options.PrinterReconciler); err != nil {
					connectionErr = err
					break
				}
			}
			if client.PrinterJobCancelSupported && snapshot.PrinterJobCommand != nil {
				if err := client.applyPrinterJobCommand(ctx, &state, identity, connection, snapshot, options.PrinterJobCanceler); err != nil {
					connectionErr = err
					break
				}
			}
			if client.PrinterQueueControlSupported && snapshot.PrinterQueueCommand != nil {
				if err := client.applyPrinterQueueCommand(ctx, &state, identity, connection, snapshot, options.PrinterQueueController); err != nil {
					connectionErr = err
					break
				}
			}
			state.SessionID = accepted.SessionID
			if err := client.handleFleetUpdate(ctx, &state, identity, connection, snapshot.FleetUpdate, fleet, coordinator, options.WriteTimeout, fleetReports); err != nil {
				connectionErr = err
				break
			}
			if snapshot.Operation != nil && fleet != nil && fleet.Busy() {
				snapshot.Operation = nil
			}
			if err := client.handleHardwareSnapshot(ctx, &state, identity, connection, snapshot, inventoryCollector, coordinator, options.WriteTimeout); err != nil {
				connectionErr = err
				break
			}
			// Observe process death before replaying an applied ACK or comparing
			// managed settings. Retry only on the next bounded heartbeat.
			browserExited := false
			if lifecycle, ok := browser.(interface{ Done() <-chan struct{} }); ok {
				select {
				case <-lifecycle.Done():
					_ = browser.Close()
					browser = nil
					browserExited = true
					browserRecoveryDue = true
					ackedRevisionID = ""
					browserAppliedRevisionID = ""
					playlistRevisionID = ""
					playlistNextAt = time.Time{}
				default:
				}
			}
			if !browserExited && options.RuntimeMode == "sway" && snapshot.Runtime != nil {
				runtimeOutcome, err := client.applyRuntimeAndAcknowledge(ctx, &state, identity, connection, snapshot.SessionID, *snapshot.Runtime, options.RuntimeApplier, runtimeReporter)
				if err != nil {
					connectionErr = err
					break
				}
				// A failed runtime ACK is truthful evidence that this artifact
				// was not applied. Keep the currently working compositor/browser
				// pair intact until a later retry is confirmed applied.
				if runtimeOutcome.Applied && snapshot.Runtime.Status == "ready" && snapshot.Runtime.Browser != nil {
					config := *snapshot.Runtime.Browser
					if managedBrowserConfig == nil || *managedBrowserConfig != config || browser == nil {
						if browser != nil {
							_ = browser.Close()
							// The old browser may have applied this revision, but its
							// target no longer exists after a restart.  Clear all target
							// state before attempting startup so a startup failure emits
							// the signed failure ACK and a later recovery navigates again.
							ackedRevisionID = ""
							browserAppliedRevisionID = ""
							playlistRevisionID = ""
							playlistNextAt = time.Time{}
						}
						managedBrowserConfig = &config
						browser, err = browserFactory(ctx, browserUserDataDir)
						if err != nil {
							// Keep the authenticated session alive so a transient
							// binary/Wayland/CDP failure can recover on a bounded later
							// heartbeat. The desired branch below emits one signed
							// failed observation instead of leaving the UI pending.
							browser = nil
						}
						if browser != nil {
							// A newly available browser must re-verify the page even
							// when an earlier unsupported/start-failed ACK exists.
							ackedRevisionID = ""
							browserAppliedRevisionID = ""
							playlistRevisionID = ""
							playlistNextAt = time.Time{}
						}
					}
				} else if runtimeOutcome.Applied && browser != nil {
					_ = browser.Close()
					browser = nil
					managedBrowserConfig = nil
					ackedRevisionID = ""
					browserAppliedRevisionID = ""
					playlistRevisionID = ""
					playlistNextAt = time.Time{}
				}
			}
			if snapshot.BrowserCommand != nil {
				if err := client.applyBrowserCommand(ctx, &state, identity, connection, &browser, browserFactory, browserUserDataDir, snapshot, &playlistIndex, &browserAppliedRevisionID, &playlistRevisionID, &playlistNextAt); err != nil {
					connectionErr = err
					break
				}
				// A failed restart has already closed the old process and its
				// command is terminal once the control plane accepts the result.
				// Schedule a bounded factory retry on a later heartbeat so a
				// transient Chromium/Wayland failure can recover without keeping a
				// stale closed browser pointer alive.
				if options.RuntimeMode == "browser" && browser == nil && state.LastBrowserCommandResult == "failed" && state.LastBrowserCommandError == "browser-restart" {
					browserRecoveryDue = true
				}
			}
			if !browserExited && options.RuntimeMode == "browser" && browserRecoveryDue && snapshot.BrowserCommand == nil {
				replacement, recoveryErr := browserFactory(ctx, browserUserDataDir)
				if recoveryErr == nil && replacement != nil {
					browser = replacement
					browserRecoveryDue = false
					ackedRevisionID = ""
					browserAppliedRevisionID = ""
					playlistRevisionID = ""
					playlistNextAt = time.Time{}
				}
			}
			if snapshot.Desired == nil {
				ackedRevisionID = ""
				browserAppliedRevisionID = ""
				playlistRevisionID = ""
				playlistNextAt = time.Time{}
			} else if browser != nil && (ackedRevisionID != snapshot.Desired.RevisionID || (snapshot.Desired.Type == "playlist-v1" && !playlistNextAt.IsZero() && !client.now().Before(playlistNextAt))) {
				if ackedRevisionID != snapshot.Desired.RevisionID {
					// A WSS reconnect clears the per-connection ACK marker, but
					// the browser and its active playlist item remain alive. Keep
					// that exact target for replay; reset only for a new revision
					// or after a browser restart/process boundary.
					if snapshot.Desired.Type != "playlist-v1" || playlistRevisionID != snapshot.Desired.RevisionID || browserAppliedRevisionID != snapshot.Desired.RevisionID {
						playlistIndex = 0
					}
				}
				if snapshot.Desired.Type == "playlist-v1" && ackedRevisionID == snapshot.Desired.RevisionID && playlistRevisionID == snapshot.Desired.RevisionID && len(snapshot.Desired.Items) > 0 {
					// Keep a failed rotation on the same item. Advance only after
					// the previous target was observed as applied.
					if browserAppliedRevisionID == snapshot.Desired.RevisionID && state.LastAppliedURL == snapshot.Desired.Items[playlistIndex].URL {
						playlistIndex = (playlistIndex + 1) % len(snapshot.Desired.Items)
					}
				}
				if err := client.applyAndAcknowledge(ctx, &state, identity, browser, connection, snapshot, &browserAppliedRevisionID, playlistIndex); err != nil {
					connectionErr = err
					break
				}
				if state.LastAckResult == "applied" {
					ackedRevisionID = snapshot.Desired.RevisionID
					playlistRevisionID = snapshot.Desired.RevisionID
					if snapshot.Desired.Type == "playlist-v1" && len(snapshot.Desired.Items) > 0 {
						playlistNextAt = client.now().Add(time.Duration(snapshot.Desired.Items[playlistIndex].DurationSeconds) * time.Second)
					} else {
						playlistNextAt = time.Time{}
					}
				} else if snapshot.Desired.Type == "playlist-v1" {
					// Avoid a hot retry loop after a failed rotation. The target
					// index remains unchanged and is retried on the next bounded
					// heartbeat.
					playlistNextAt = client.now().Add(options.HeartbeatInterval)
				}
			} else if snapshot.Desired != nil && browser == nil && ackedRevisionID != snapshot.Desired.RevisionID {
				// Raw Sway has no agent-managed target. Report explicit unsupported
				// observation rather than a false applied ACK.
				if err := client.sendUnsupportedDesiredAck(ctx, &state, identity, connection, snapshot, "browser-unavailable"); err != nil {
					connectionErr = err
					break
				}
				ackedRevisionID = snapshot.Desired.RevisionID
			}
			if client.IdleScreenSupported && idleRuntime != nil {
				if err := client.applyIdleAndAcknowledge(ctx, &state, identity, connection, snapshot, idleRuntime); err != nil {
					connectionErr = err
					break
				}
			}
			if client.RemoteDesktopSupported && options.RemoteDesktop != nil && snapshot.RemoteDesktop != nil {
				if err := client.applyRemoteDesktopAndAcknowledge(ctx, &state, identity, connection, snapshot, options.RemoteDesktop); err != nil {
					connectionErr = err
					break
				}
			} else if client.RemoteDesktopSupported && options.RemoteDesktop != nil && snapshot.RemoteDesktop == nil {
				if result := options.RemoteDesktop.Stop(); result.Result == "failed" {
					connectionErr = fmt.Errorf("remote desktop cleanup failed")
					break
				}
			}
			if client.RemoteDesktopSupported && options.RemoteDesktop != nil && snapshot.RemoteDesktopPoll != nil {
				remotePollEnabled = snapshot.RemoteDesktopPoll.Enabled
				remotePollInterval = remoteDesktopPollInterval(snapshot.RemoteDesktopPoll)
				if remotePollEnabled && remotePollNextAt.IsZero() {
					remotePollNextAt = client.now().Add(remotePollInterval)
				}
				if !remotePollEnabled {
					remotePollNextAt = time.Time{}
					remotePollInterval = 0
				}
			} else {
				remotePollEnabled = false
				remotePollNextAt = time.Time{}
				remotePollInterval = 0
			}
			state.SessionID = accepted.SessionID
			state.HeartbeatSequence = sequence
			state.LastHeartbeatAt = observedAt
			if err := SaveStateAtomic(client.StateDir, state); err != nil {
				connectionErr = err
				break
			}
			if printerReporter != nil && printerReportDue(state, client.now()) {
				if err := client.sendPrinterReport(ctx, &state, identity, connection, accepted.SessionID, printerReporter); err != nil {
					connectionErr = err
					break
				}
			}
			if client.PrinterStatisticsSupported && printerStatisticsReporter != nil && printerStatisticsDue(state, client.now()) {
				if err := client.sendPrinterStatistics(ctx, &state, identity, connection, accepted.SessionID, printerStatisticsReporter); err != nil {
					connectionErr = err
					break
				}
			}
			if client.PrinterJobsSupported && printerJobsReporter != nil && printerJobsDue(state, client.now()) {
				if err := client.sendPrinterJobs(ctx, &state, identity, connection, accepted.SessionID, printerJobsReporter); err != nil {
					connectionErr = err
					break
				}
			}
			// Polls are interleaved with, rather than used in place of, the
			// normal heartbeat. Keep this absolute deadline stable while the
			// one-second poll loop runs so repeated polls cannot starve the
			// 15-second session heartbeat.
			nextHeartbeatAt = client.now().Add(options.HeartbeatInterval)
		waitForEvent:
			for {
				wait := max(nextHeartbeatAt.Sub(client.now()), 0)
				if !playlistNextAt.IsZero() {
					until := playlistNextAt.Sub(client.now())
					if until > 0 && until < wait {
						wait = until
					}
					if until <= 0 {
						wait = time.Millisecond
					}
				}
				if remotePollEnabled && !remotePollNextAt.IsZero() {
					until := remotePollNextAt.Sub(client.now())
					if until <= 0 {
						wait = 0
					} else if until < wait {
						wait = until
					}
				}
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					cleanup()
					return ctx.Err()
				case <-timer.C:
				}
				if remotePollEnabled && !remotePollNextAt.IsZero() && !client.now().Before(remotePollNextAt) {
					remotePollSequence++
					pollResult, pollErr := client.pollRemoteDesktopAndApply(ctx, &state, identity, connection, accepted.SessionID, remotePollSequence, options.RemoteDesktop)
					if pollErr != nil {
						connectionErr = pollErr
						break waitForEvent
					}
					if !pollResult.Enabled {
						// A policy disable is authoritative and must retire the local
						// relay immediately, without waiting for the next heartbeat.
						remotePollEnabled = false
						remotePollNextAt = time.Time{}
						remotePollInterval = 0
					} else {
						if remotePollInterval <= 0 {
							remotePollInterval = RemoteDesktopPollInterval
						}
						remotePollNextAt = client.now().Add(remotePollInterval)
					}
					// Keep this managed socket open and wait for the next poll or
					// normal heartbeat. A poll must not turn into a heartbeat.
					continue
				}
				break
			}
			if connectionErr != nil {
				break
			}
		}
		cleanup()
		if options.RemoteDesktop != nil {
			_ = options.RemoteDesktop.Stop()
		}
		if permanentSessionError(connectionErr) {
			return connectionErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(options.ReconnectDelay):
		}
	}
}

func remoteDesktopPollInterval(policy *RemoteDesktopPollPolicy) time.Duration {
	if policy == nil || policy.IntervalMs <= 0 {
		return RemoteDesktopPollInterval
	}
	interval := time.Duration(policy.IntervalMs) * time.Millisecond
	// The server controls this value. Keep the client bounded if a future
	// compatible server sends an unexpected policy value.
	if interval < 750*time.Millisecond || interval > 5*time.Second {
		return RemoteDesktopPollInterval
	}
	return interval
}

func (client Client) pollRemoteDesktopAndApply(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, sequence uint64, manager *RemoteDesktopManager) (RemoteDesktopPollResult, error) {
	if manager == nil || connection == nil {
		return RemoteDesktopPollResult{}, fmt.Errorf("remote desktop poll runtime is unavailable")
	}
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	poll := RemoteDesktopPoll{
		Version: ProtocolVersion, Type: "remote-desktop.poll", Profile: identityProfile(state.PublicIdentityRef),
		SessionID: sessionID, DeviceID: state.DeviceID, Sequence: sequence, ObservedAt: observedAt,
	}
	var err error
	poll.Signature, err = encodeIdentitySignature(identity, RemoteDesktopPollCanonical(poll))
	if err != nil {
		return RemoteDesktopPollResult{}, err
	}
	if poll.Signature == "" {
		return RemoteDesktopPollResult{}, fmt.Errorf("%w: empty remote poll signature", ErrIdentity)
	}
	if err := writeSessionMessage(connection, poll, sessionMessageTimeout); err != nil {
		return RemoteDesktopPollResult{}, err
	}
	var result RemoteDesktopPollResult
	if err := readSessionMessage(ctx, connection, &result); err != nil {
		return RemoteDesktopPollResult{}, err
	}
	if result.Version != ProtocolVersion || result.Type != "remote-desktop.poll.result" || result.SessionID != sessionID || result.DeviceID != state.DeviceID || result.Sequence != sequence || (!result.Enabled && result.RemoteDesktop != nil) {
		return RemoteDesktopPollResult{}, fmt.Errorf("remote desktop poll result is invalid")
	}
	if result.RemoteDesktop != nil {
		if err := ValidateRemoteDesktopDesired(*result.RemoteDesktop, client.now()); err != nil {
			return RemoteDesktopPollResult{}, err
		}
		snapshot := DesiredSnapshot{Version: ProtocolVersion, Type: "desired.snapshot", SessionID: sessionID, DeviceID: state.DeviceID, RemoteDesktop: result.RemoteDesktop}
		if err := client.applyRemoteDesktopAndAcknowledge(ctx, state, identity, connection, snapshot, manager); err != nil {
			return RemoteDesktopPollResult{}, err
		}
	} else if stopResult := manager.Stop(); stopResult.Result == "failed" {
		return RemoteDesktopPollResult{}, fmt.Errorf("remote desktop cleanup failed")
	}
	return result, nil
}

func (client Client) applyRemoteDesktopAndAcknowledge(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, snapshot DesiredSnapshot, manager *RemoteDesktopManager) error {
	desired := snapshot.RemoteDesktop
	if desired == nil {
		return nil
	}
	result := manager.Apply(ctx, desired)
	if result.Noop {
		return nil
	}
	category := (*string)(nil)
	if result.Result != "applied" {
		categoryValue := result.ErrorCategory
		if !remoteDesktopFailureCategories[categoryValue] {
			categoryValue = "unsupported"
		}
		category = &categoryValue
	}
	sequence := state.RemoteDesktopAckSequence + 1
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	ack := RemoteDesktopAck{Version: ProtocolVersion, Type: "remote-desktop.ack", Profile: identity.Profile(), SessionID: snapshot.SessionID, DeviceID: state.DeviceID, RemoteSessionID: desired.SessionID, Action: desired.Action, Result: result.Result, ErrorCategory: category, ObservedAt: observedAt, Sequence: sequence}
	var signingError error
	ack.Signature, signingError = encodeIdentitySignature(identity, RemoteDesktopAckCanonical(ack))
	if signingError != nil {
		return signingError
	}
	if ack.Signature == "" {
		return fmt.Errorf("sign remote desktop acknowledgement")
	}
	state.RemoteDesktopAckSequence = sequence
	state.LastRemoteDesktopSessionID, state.LastRemoteDesktopAction, state.LastRemoteDesktopResult, state.LastRemoteDesktopAckAt = desired.SessionID, desired.Action, result.Result, observedAt
	if category == nil {
		state.LastRemoteDesktopError = ""
	} else {
		state.LastRemoteDesktopError = *category
	}
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, ack, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted struct {
		Version         int    `json:"version"`
		Type            string `json:"type"`
		SessionID       string `json:"sessionId"`
		DeviceID        string `json:"deviceId"`
		RemoteSessionID string `json:"remoteSessionId"`
		Action          string `json:"action"`
		Result          string `json:"result"`
		Sequence        uint64 `json:"sequence"`
		Disposition     string `json:"disposition"`
	}
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "remote-desktop.ack.accepted" || accepted.SessionID != ack.SessionID || accepted.DeviceID != ack.DeviceID || accepted.RemoteSessionID != ack.RemoteSessionID || accepted.Action != ack.Action || accepted.Result != ack.Result || accepted.Sequence != ack.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate" && accepted.Disposition != "stale") {
		return fmt.Errorf("remote desktop acknowledgement was not accepted")
	}
	return SaveStateAtomic(client.StateDir, *state)
}

func (client Client) applyAndAcknowledge(ctx context.Context, state *State, identity Identity, browser Browser, connection *websocket.Conn, snapshot DesiredSnapshot, browserAppliedRevisionID *string, playlistIndex int) error {
	if snapshot.Desired == nil {
		return nil
	}
	desired := snapshot.Desired
	targetURL := desired.URL
	if desired.Type == "playlist-v1" {
		if playlistIndex < 0 || playlistIndex >= len(desired.Items) {
			return fmt.Errorf("playlist index is invalid")
		}
		targetURL = desired.Items[playlistIndex].URL
	}
	observedURL := ""
	result := "applied"
	var category *string
	if browserAppliedRevisionID != nil && *browserAppliedRevisionID == desired.RevisionID && state.LastAppliedURL == targetURL {
		// Reconnecting after a response loss replays the snapshot without
		// navigating the same live tab a second time. The marker is never
		// restored from disk, so a fresh process always verifies the page.
		observedURL = state.LastAppliedURL
	} else {
		var navigateErr error
		observedURL, navigateErr = browser.Navigate(ctx, targetURL)
		if navigateErr != nil || observedURL != targetURL {
			result = "failed"
			categoryValue := "browser-navigation"
			if navigateErr == nil {
				categoryValue = "observed-url-mismatch"
			}
			category = &categoryValue
			if navigateErr != nil {
				observedURL = ""
			}
		}
	}
	sequence := state.AckSequence + 1
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	ack := DesiredAck{
		Version: ProtocolVersion, Type: "desired.ack", Profile: identity.Profile(),
		SessionID: snapshot.SessionID, DeviceID: state.DeviceID,
		GroupID: desired.GroupID, RevisionID: desired.RevisionID, Revision: desired.Revision,
		Result: result, ObservedURL: observedURL, ErrorCategory: category,
		ObservedAt: observedAt, Sequence: sequence,
	}
	var signingError error
	ack.Signature, signingError = encodeIdentitySignature(identity, DesiredAckCanonical(ack))
	if signingError != nil {
		return signingError
	}
	if ack.Signature == "" {
		return fmt.Errorf("sign desired acknowledgement")
	}
	// Save before sending. Socket reconnects replay the ACK for this live
	// browser; a new process verifies its newly launched page again.
	state.AckSequence = sequence
	state.LastAckResult = result
	state.LastAckAt = observedAt
	state.LastRevisionID = desired.RevisionID
	state.LastRevision = desired.Revision
	if result == "applied" {
		state.LastAppliedURL = observedURL
		if browserAppliedRevisionID != nil {
			*browserAppliedRevisionID = desired.RevisionID
		}
	} else {
		state.LastAppliedURL = ""
	}
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, ack, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted struct {
		Version     int    `json:"version"`
		Type        string `json:"type"`
		SessionID   string `json:"sessionId"`
		DeviceID    string `json:"deviceId"`
		GroupID     string `json:"groupId"`
		RevisionID  string `json:"revisionId"`
		Revision    uint64 `json:"revision"`
		Result      string `json:"result"`
		Sequence    uint64 `json:"sequence"`
		Disposition string `json:"disposition"`
	}
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "desired.ack.accepted" || accepted.SessionID != snapshot.SessionID || accepted.DeviceID != state.DeviceID || accepted.GroupID != desired.GroupID || accepted.RevisionID != desired.RevisionID || accepted.Revision != desired.Revision || accepted.Result != result || accepted.Sequence != sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate" && accepted.Disposition != "stale") {
		return fmt.Errorf("desired acknowledgement was not accepted")
	}
	return nil
}

// applyBrowserCommand executes exactly one signed, bounded browser action. The
// durable state write happens before the result is sent, so a lost response is
// replayed without touching the browser a second time.
func (client Client) applyBrowserCommand(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, browser *Browser, factory BrowserFactory, userDataDir string, snapshot DesiredSnapshot, playlistIndex *int, browserAppliedRevisionID, playlistRevisionID *string, playlistNextAt *time.Time) error {
	command := snapshot.BrowserCommand
	if command == nil {
		return nil
	}
	replay := state.LastBrowserCommandID == command.CommandID && state.LastBrowserCommandHash == command.PayloadHash
	if err := command.Validate(client.now(), replay); err != nil {
		return err
	}
	if command.Profile != identity.Profile() {
		return fmt.Errorf("browser command identity profile mismatch")
	}
	if replay {
		if state.LastBrowserCommandAccepted {
			return nil
		}
	} else {
		state.BrowserCommandSequence++
		state.LastBrowserCommandID = command.CommandID
		state.LastBrowserCommandHash = command.PayloadHash
		state.LastBrowserCommandResult = "applied"
		state.LastBrowserCommandError = ""
		state.LastBrowserCommandObservedURL = ""
		state.LastBrowserCommandZoom = nil
		state.LastBrowserCommandAt = client.now().UTC().Format(time.RFC3339Nano)
		state.LastBrowserCommandAccepted = false
		observedURL := ""
		var observedZoom *int
		result := "applied"
		category := ""
		if *browser == nil {
			result = "failed"
			category = "browser-unsupported"
		} else {
			var actionErr error
			switch command.Action {
			case "reload":
				observedURL, actionErr = (*browser).Reload(ctx)
			case "return-to-assigned":
				if snapshot.Desired == nil {
					actionErr = errors.New("no assigned presentation")
				} else {
					target := snapshot.Desired.URL
					if snapshot.Desired.Type == "playlist-v1" && len(snapshot.Desired.Items) > 0 {
						target = snapshot.Desired.Items[0].URL
					}
					observedURL, actionErr = (*browser).Navigate(ctx, target)
					if actionErr == nil && observedURL == target {
						state.LastAppliedURL = observedURL
						*playlistIndex = 0
						*browserAppliedRevisionID = snapshot.Desired.RevisionID
						*playlistRevisionID = snapshot.Desired.RevisionID
						*playlistNextAt = client.playlistNextDeadline(snapshot, *playlistIndex)
					}
				}
			case "set-zoom":
				var accepted int
				observedURL, accepted, actionErr = (*browser).SetZoom(ctx, *command.ZoomPercent)
				if actionErr == nil {
					if accepted != *command.ZoomPercent {
						actionErr = fmt.Errorf("browser accepted zoom %d instead of requested %d", accepted, *command.ZoomPercent)
					} else {
						observedZoom = &accepted
					}
				}
			case "restart-browser":
				oldBrowser := *browser
				*browser = nil
				_ = oldBrowser.Close()
				if factory == nil {
					actionErr = errors.New("browser factory unavailable")
				} else {
					var replacement Browser
					replacement, actionErr = factory(ctx, userDataDir)
					if actionErr == nil && replacement == nil {
						actionErr = errors.New("browser factory returned no browser")
					}
					if actionErr == nil && snapshot.Desired != nil {
						target := snapshot.Desired.URL
						if snapshot.Desired.Type == "playlist-v1" && len(snapshot.Desired.Items) > 0 {
							target = snapshot.Desired.Items[0].URL
						}
						observedURL, actionErr = replacement.Navigate(ctx, target)
						if actionErr == nil && observedURL == target {
							state.LastAppliedURL = observedURL
							*playlistIndex = 0
							*browserAppliedRevisionID = snapshot.Desired.RevisionID
							*playlistRevisionID = snapshot.Desired.RevisionID
							*playlistNextAt = client.playlistNextDeadline(snapshot, *playlistIndex)
						}
					}
					if actionErr == nil {
						*browser = replacement
					} else if replacement != nil {
						_ = replacement.Close()
					}
				}
			default:
				actionErr = errors.New("unsupported browser command")
			}
			if actionErr != nil || (command.Action == "return-to-assigned" || command.Action == "restart-browser") && snapshot.Desired != nil && observedURL == "" {
				result = "failed"
				switch command.Action {
				case "set-zoom":
					category = "browser-zoom"
				case "restart-browser":
					category = "browser-restart"
				case "return-to-assigned":
					category = "browser-navigation"
				default:
					category = "browser-observation"
				}
			}
		}
		state.LastBrowserCommandResult = result
		state.LastBrowserCommandError = category
		state.LastBrowserCommandObservedURL = observedURL
		state.LastBrowserCommandZoom = observedZoom
		if err := SaveStateAtomic(client.StateDir, *state); err != nil {
			return err
		}
	}
	category := (*string)(nil)
	if state.LastBrowserCommandResult == "failed" {
		value := state.LastBrowserCommandError
		category = &value
	}
	result := BrowserCommandResult{Version: ProtocolVersion, Type: BrowserCommandResultType, Profile: identity.Profile(), SessionID: snapshot.SessionID, DeviceID: state.DeviceID, CommandID: command.CommandID, Action: command.Action, PayloadHash: command.PayloadHash, Result: state.LastBrowserCommandResult, ErrorCategory: category, ObservedURL: state.LastBrowserCommandObservedURL, ZoomPercent: state.LastBrowserCommandZoom, ObservedAt: state.LastBrowserCommandAt, Sequence: state.BrowserCommandSequence}
	var err error
	result.Signature, err = encodeIdentitySignature(identity, BrowserCommandResultCanonical(result))
	if err != nil {
		return err
	}
	if err := writeSessionMessage(connection, result, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted struct {
		Version     int    `json:"version"`
		Type        string `json:"type"`
		SessionID   string `json:"sessionId"`
		DeviceID    string `json:"deviceId"`
		CommandID   string `json:"commandId"`
		Action      string `json:"action"`
		Sequence    uint64 `json:"sequence"`
		Disposition string `json:"disposition"`
	}
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "browser.command.result.accepted" || accepted.SessionID != snapshot.SessionID || accepted.DeviceID != state.DeviceID || accepted.CommandID != command.CommandID || accepted.Action != command.Action || accepted.Sequence != result.Sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate") {
		return fmt.Errorf("browser command result was not accepted")
	}
	state.LastBrowserCommandAccepted = true
	return SaveStateAtomic(client.StateDir, *state)
}

func (client Client) playlistNextDeadline(snapshot DesiredSnapshot, index int) time.Time {
	if snapshot.Desired == nil || snapshot.Desired.Type != "playlist-v1" || len(snapshot.Desired.Items) == 0 || index < 0 || index >= len(snapshot.Desired.Items) {
		return time.Time{}
	}
	return client.now().Add(time.Duration(snapshot.Desired.Items[index].DurationSeconds) * time.Second)
}

func (client Client) sendUnsupportedDesiredAck(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, snapshot DesiredSnapshot, categoryValue string) error {
	if snapshot.Desired == nil {
		return nil
	}
	sequence := state.AckSequence + 1
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	category := categoryValue
	ack := DesiredAck{Version: ProtocolVersion, Type: "desired.ack", Profile: identity.Profile(), SessionID: snapshot.SessionID, DeviceID: state.DeviceID, GroupID: snapshot.Desired.GroupID, RevisionID: snapshot.Desired.RevisionID, Revision: snapshot.Desired.Revision, Result: "failed", ObservedURL: "", ErrorCategory: &category, ObservedAt: observedAt, Sequence: sequence}
	var signingError error
	ack.Signature, signingError = encodeIdentitySignature(identity, DesiredAckCanonical(ack))
	if signingError != nil {
		return signingError
	}
	if ack.Signature == "" {
		return fmt.Errorf("sign desired acknowledgement")
	}
	state.AckSequence, state.LastAckResult, state.LastAckAt = sequence, "failed", observedAt
	state.LastRevisionID, state.LastRevision = snapshot.Desired.RevisionID, snapshot.Desired.Revision
	state.LastAppliedURL = ""
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, ack, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted struct {
		Version     int    `json:"version"`
		Type        string `json:"type"`
		SessionID   string `json:"sessionId"`
		DeviceID    string `json:"deviceId"`
		GroupID     string `json:"groupId"`
		RevisionID  string `json:"revisionId"`
		Revision    uint64 `json:"revision"`
		Result      string `json:"result"`
		Sequence    uint64 `json:"sequence"`
		Disposition string `json:"disposition"`
	}
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "desired.ack.accepted" || accepted.SessionID != snapshot.SessionID || accepted.DeviceID != state.DeviceID || accepted.GroupID != snapshot.Desired.GroupID || accepted.RevisionID != snapshot.Desired.RevisionID || accepted.Revision != snapshot.Desired.Revision || accepted.Result != "failed" || accepted.Sequence != sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate" && accepted.Disposition != "stale") {
		return fmt.Errorf("desired acknowledgement was not accepted")
	}
	return nil
}

type runtimeApplyOutcome struct{ Applied bool }

func (client Client) applyRuntimeAndAcknowledge(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, artifact RuntimeArtifact, applier RuntimeApplier, reporter *runtimeDiagnosticReporter) (runtimeApplyOutcome, error) {
	if artifact.Status != "ready" {
		return runtimeApplyOutcome{}, nil
	}
	if state.LastRuntimeArtifactHash == artifact.ArtifactHash && state.LastRuntimeAckResult == "applied" {
		if state.LastRuntimeAckAccepted {
			// Both application and server acceptance are durable. A reconnect or
			// repeated heartbeat therefore needs no write and no unbounded ACK.
			return runtimeApplyOutcome{Applied: true}, nil
		}
		// The applier completed and persisted its result before the original
		// ACK was written or accepted. Replay the ACK after reconnect, but never
		// apply the same artifact a second time.
		if err := client.sendRuntimeAck(ctx, state, identity, connection, sessionID, artifact, "applied", nil); err != nil {
			return runtimeApplyOutcome{}, err
		}
		return runtimeApplyOutcome{Applied: true}, nil
	}
	result := "applied"
	var category *string
	if err := applier.Apply(ctx, artifact); err != nil {
		result = "failed"
		categoryValue := runtimeErrorCategory(err)
		category = &categoryValue
		reporter.failure(artifact, categoryValue, err)
	} else {
		reporter.applied(artifact)
	}
	if err := client.sendRuntimeAck(ctx, state, identity, connection, sessionID, artifact, result, category); err != nil {
		return runtimeApplyOutcome{}, err
	}
	return runtimeApplyOutcome{Applied: result == "applied"}, nil
}

func runtimeErrorCategory(err error) string {
	message := strings.ToLower(err.Error())
	if commandErr, ok := errors.AsType[*runtimeCommandError](err); ok {
		// Keep command output local and out of category selection: an arbitrary
		// validator message must not turn a validation failure into reload or
		// filesystem protocol evidence.
		prefix := message
		if before, _, ok := strings.Cut(message, "runtime command "); ok {
			prefix = before
		}
		if strings.Contains(strings.ToLower(commandErr.command), "swaymsg") || strings.Contains(prefix, "reload") {
			return "runtime-reload"
		}
		return "runtime-validation"
	}
	if strings.Contains(message, "reload") || strings.Contains(message, "swaymsg") {
		return "runtime-reload"
	}
	if strings.Contains(message, "file") || strings.Contains(message, "directory") || strings.Contains(message, "socket") || strings.Contains(message, "path") {
		return "runtime-filesystem"
	}
	return "runtime-validation"
}

func idleErrorCategory(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "timeout"):
		return "idle-runtime-timeout"
	case strings.Contains(message, "file") || strings.Contains(message, "directory") || strings.Contains(message, "document"):
		return "idle-runtime-filesystem"
	case strings.Contains(message, "validation") || strings.Contains(message, "color") || strings.Contains(message, "message"):
		return "idle-runtime-validation"
	case strings.Contains(message, "start") || strings.Contains(message, "chromium") || strings.Contains(message, "sway"):
		return "idle-runtime-start"
	default:
		return "idle-runtime-unavailable"
	}
}

type IdleDiagnostic struct {
	ErrorCategory string
	Stage         string
}

func idleErrorStage(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.HasPrefix(message, "idle graphical environment"):
		return "graphical-environment"
	case strings.HasPrefix(message, "idle sway environment"):
		return "sway-environment"
	case strings.HasPrefix(message, "start idle chromium"):
		return "chromium-start"
	case strings.HasPrefix(message, "navigate idle document"):
		return "chromium-navigation"
	case strings.HasPrefix(message, "wait for idle input"):
		return "input-wait"
	case strings.HasPrefix(message, "clean idle chromium profile"):
		return "profile-cleanup"
	case strings.HasPrefix(message, "idle inactivity supervisor"):
		return "swayidle-start"
	case strings.Contains(message, "asset"):
		return "asset-cache"
	case strings.Contains(message, "file") || strings.Contains(message, "directory") || strings.Contains(message, "document"):
		return "filesystem"
	case strings.Contains(message, "validation"):
		return "validation"
	default:
		return "unavailable"
	}
}

func (client Client) reportIdleFailure(err error, category string) {
	if client.IdleDiagnostics != nil {
		client.IdleDiagnostics(IdleDiagnostic{ErrorCategory: category, Stage: idleErrorStage(err)})
	}
}

func (client Client) applyIdleAndAcknowledge(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, snapshot DesiredSnapshot, runtime IdleRuntime) error {
	desired := snapshot.Idle
	if desired == nil && (state.LastIdleScreenID == "" || (state.LastIdleRemoved && state.LastIdleAckResult == "applied" && state.LastIdleAckAccepted)) {
		return nil
	}
	alreadyApplied := desired != nil && state.LastIdleScreenID == desired.IdleScreenID && state.LastIdleRevisionID == desired.RevisionID && state.LastIdlePayloadHash == desired.PayloadHash && state.LastIdleAckResult == "applied" && state.LastIdleAckAccepted && !state.LastIdleRemoved
	result := "applied"
	var category *string
	if desired == nil {
		if err := runtime.Apply(ctx, nil); err != nil {
			result = "failed"
			categoryValue := idleErrorCategory(err)
			category = &categoryValue
			client.reportIdleFailure(err, categoryValue)
		}
	} else {
		if err := runtime.Apply(ctx, desired); err != nil {
			result = "failed"
			categoryValue := idleErrorCategory(err)
			category = &categoryValue
			client.reportIdleFailure(err, categoryValue)
		} else if alreadyApplied {
			return nil
		}
	}
	idleScreenID, revisionID, payloadHash := state.LastIdleScreenID, state.LastIdleRevisionID, state.LastIdlePayloadHash
	if desired != nil {
		idleScreenID, revisionID, payloadHash = desired.IdleScreenID, desired.RevisionID, desired.PayloadHash
	}
	if idleScreenID == "" || revisionID == "" || payloadHash == "" {
		return fmt.Errorf("idle acknowledgement identity is unavailable")
	}
	sequence := state.IdleAckSequence + 1
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	ack := IdleAck{Version: ProtocolVersion, Type: "idle.desired.ack", Profile: identity.Profile(), SessionID: snapshot.SessionID, DeviceID: state.DeviceID, IdleScreenID: idleScreenID, RevisionID: revisionID, PayloadHash: payloadHash, Result: result, ErrorCategory: category, ObservedAt: observedAt, Sequence: sequence}
	var signingError error
	ack.Signature, signingError = encodeIdentitySignature(identity, IdleAckCanonical(ack))
	if signingError != nil {
		return signingError
	}
	if ack.Signature == "" {
		return fmt.Errorf("sign idle acknowledgement")
	}
	state.IdleAckSequence = sequence
	state.LastIdleScreenID, state.LastIdleRevisionID, state.LastIdlePayloadHash = idleScreenID, revisionID, payloadHash
	state.LastIdleAckResult, state.LastIdleAckError, state.LastIdleAckAt = result, "", observedAt
	if category != nil {
		state.LastIdleAckError = *category
	}
	state.LastIdleAckAccepted = false
	state.LastIdleRemoved = false
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, ack, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted struct {
		Version      int    `json:"version"`
		Type         string `json:"type"`
		SessionID    string `json:"sessionId"`
		DeviceID     string `json:"deviceId"`
		IdleScreenID string `json:"idleScreenId"`
		RevisionID   string `json:"revisionId"`
		PayloadHash  string `json:"payloadHash"`
		Result       string `json:"result"`
		Sequence     uint64 `json:"sequence"`
		Disposition  string `json:"disposition"`
	}
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "idle.desired.ack.accepted" || accepted.SessionID != ack.SessionID || accepted.DeviceID != state.DeviceID || accepted.IdleScreenID != idleScreenID || accepted.RevisionID != revisionID || accepted.PayloadHash != payloadHash || accepted.Result != result || accepted.Sequence != sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate" && accepted.Disposition != "stale") {
		return fmt.Errorf("idle acknowledgement was not accepted")
	}
	state.LastIdleAckAccepted = accepted.Disposition == "accepted" || accepted.Disposition == "duplicate"
	state.LastIdleRemoved = desired == nil && result == "applied" && state.LastIdleAckAccepted
	return SaveStateAtomic(client.StateDir, *state)
}

func (client Client) sendRuntimeAck(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, sessionID string, artifact RuntimeArtifact, result string, category *string) error {
	sequence := state.RuntimeAckSequence + 1
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	ack := RuntimeAck{
		Version: ProtocolVersion, Type: "runtime.ack", Profile: identity.Profile(),
		SessionID: sessionID, DeviceID: state.DeviceID,
		ArtifactRevision: artifact.ArtifactRevision, ArtifactHash: artifact.ArtifactHash,
		Result: result, ErrorCategory: category, ObservedAt: observedAt, Sequence: sequence,
	}
	if ack.SessionID == "" {
		return fmt.Errorf("runtime acknowledgement session is unavailable")
	}
	var signingError error
	ack.Signature, signingError = encodeIdentitySignature(identity, RuntimeAckCanonical(ack))
	if signingError != nil {
		return signingError
	}
	if ack.Signature == "" {
		return fmt.Errorf("sign runtime acknowledgement")
	}
	state.RuntimeAckSequence = sequence
	state.LastRuntimeArtifactRevision = artifact.ArtifactRevision
	state.LastRuntimeArtifactHash = artifact.ArtifactHash
	state.LastRuntimeAckResult = result
	state.LastRuntimeAckAt = observedAt
	state.LastRuntimeAckAccepted = false
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	if err := writeSessionMessage(connection, ack, sessionMessageTimeout); err != nil {
		return err
	}
	var accepted struct {
		Version          int    `json:"version"`
		Type             string `json:"type"`
		SessionID        string `json:"sessionId"`
		DeviceID         string `json:"deviceId"`
		ArtifactRevision string `json:"artifactRevision"`
		ArtifactHash     string `json:"artifactHash"`
		Result           string `json:"result"`
		Sequence         uint64 `json:"sequence"`
		Disposition      string `json:"disposition"`
	}
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		return err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "runtime.ack.accepted" || accepted.SessionID != ack.SessionID || accepted.DeviceID != state.DeviceID || accepted.ArtifactRevision != artifact.ArtifactRevision || accepted.ArtifactHash != artifact.ArtifactHash || accepted.Result != result || accepted.Sequence != sequence || (accepted.Disposition != "accepted" && accepted.Disposition != "duplicate" && accepted.Disposition != "older" && accepted.Disposition != "stale") {
		return fmt.Errorf("runtime acknowledgement was not accepted")
	}
	state.LastRuntimeAckAccepted = accepted.Disposition == "accepted" || accepted.Disposition == "duplicate"
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	return nil
}
