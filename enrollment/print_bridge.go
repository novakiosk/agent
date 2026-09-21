package enrollment

import (
	"context"
	"fmt"
	"time"

	"github.com/novakiosk/agent/cupsreconcile"
)

// PrintBridgeOptions is deliberately narrower than RunOptions. A bridge has
// no browser, runtime applier, host inventory collector, or operation
// coordinator. It maintains the signed printer session, reports evidence,
// reconciles queues, and handles authorized job and queue commands.
type PrintBridgeOptions struct {
	HeartbeatInterval         time.Duration
	ReconnectDelay            time.Duration
	WriteTimeout              time.Duration
	PrinterReporter           PrinterReporter
	PrinterStatisticsReporter PrinterStatisticsReporter
	PrinterJobsReporter       PrinterJobsReporter
	PrinterJobCanceler        PrinterJobCanceler
	PrinterQueueController    PrinterQueueController
	PrinterReconciler         cupsreconcile.Applier
}

func (options PrintBridgeOptions) normalized() (PrintBridgeOptions, error) {
	if options.HeartbeatInterval <= 0 {
		options.HeartbeatInterval = 15 * time.Second
	}
	if options.HeartbeatInterval > 24*time.Hour {
		return PrintBridgeOptions{}, fmt.Errorf("heartbeat interval is out of bounds")
	}
	if options.ReconnectDelay <= 0 {
		options.ReconnectDelay = time.Second
	}
	if options.ReconnectDelay > 30*time.Second {
		return PrintBridgeOptions{}, fmt.Errorf("reconnect delay is out of bounds")
	}
	if options.WriteTimeout <= 0 || options.WriteTimeout > 30*time.Second {
		options.WriteTimeout = sessionMessageTimeout
	}
	if options.PrinterReporter == nil {
		return PrintBridgeOptions{}, fmt.Errorf("printer reporter is required")
	}
	return options, nil
}

// PrintBridge maintains the printer session and rejects kiosk-only state.
func (client Client) PrintBridge(ctx context.Context, options PrintBridgeOptions) error {
	options, err := options.normalized()
	if err != nil {
		return err
	}
	if client.PrinterReconcileSupported && options.PrinterReconciler == nil {
		return fmt.Errorf("printer reconciler is required")
	}
	state, err := LoadState(client.StateDir)
	if err != nil {
		return err
	}
	if state.Status != "Managed" {
		return fmt.Errorf("managed print-server state is required")
	}
	if EffectiveDeviceKind(state.DeviceKind) != DeviceKindPrintServer {
		return fmt.Errorf("print-bridge requires print-server state; kiosk state must use novakiosk-agent run")
	}
	identity, err := LoadIdentity(client.StateDir)
	if err != nil {
		return err
	}
	if identity.DeviceID != state.DeviceID || state.PublicIdentityRef != identity.PublicIdentityRef {
		return fmt.Errorf("managed state identity does not match local identity")
	}

	sequence := state.HeartbeatSequence
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
		connectionErr := error(nil)
		rejectedSnapshot := false
		for {
			sequence++
			observedAt := client.now().UTC().Format(time.RFC3339Nano)
			heartbeat := Heartbeat{
				Version: ProtocolVersion, Type: "session.heartbeat", Profile: ProvisionalIdentityProfile,
				SessionID: accepted.SessionID, DeviceID: state.DeviceID, Sequence: sequence, ObservedAt: observedAt, DisplayMode: DisplayModeUnknown,
			}
			heartbeat.Signature, err = encodeIdentitySignature(identity, HeartbeatCanonical(heartbeat))
			if err != nil {
				connectionErr = err
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
			if err := validateDesiredSnapshotAt(snapshot, accepted.SessionID, state.DeviceID, client.now(), false, false); err != nil {
				connectionErr = fmt.Errorf("print-bridge rejected desired snapshot: %w", err)
				rejectedSnapshot = true
				break
			}
			if snapshot.Desired != nil || snapshot.Runtime != nil || snapshot.Operation != nil || snapshot.Idle != nil || snapshot.BrowserCommand != nil || snapshot.RemoteDesktop != nil || snapshot.RemoteDesktopPoll != nil {
				connectionErr = fmt.Errorf("print-server session delivered non-null kiosk state")
				rejectedSnapshot = true
				break
			}
			if client.PrinterReconcileSupported {
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
			state.HeartbeatSequence = sequence
			state.LastHeartbeatAt = observedAt
			if err := SaveStateAtomic(client.StateDir, state); err != nil {
				connectionErr = err
				break
			}
			if printerReportDue(state, client.now()) {
				if err := client.sendPrinterReport(ctx, &state, identity, connection, accepted.SessionID, options.PrinterReporter); err != nil {
					connectionErr = err
					break
				}
			}
			if client.PrinterStatisticsSupported && options.PrinterStatisticsReporter != nil && printerStatisticsDue(state, client.now()) {
				if err := client.sendPrinterStatistics(ctx, &state, identity, connection, accepted.SessionID, options.PrinterStatisticsReporter); err != nil {
					connectionErr = err
					break
				}
			}
			if client.PrinterJobsSupported && options.PrinterJobsReporter != nil && printerJobsDue(state, client.now()) {
				if err := client.sendPrinterJobs(ctx, &state, identity, connection, accepted.SessionID, options.PrinterJobsReporter); err != nil {
					connectionErr = err
					break
				}
			}
			select {
			case <-ctx.Done():
				cleanup()
				return ctx.Err()
			case <-time.After(options.HeartbeatInterval):
			}
		}
		cleanup()
		if rejectedSnapshot || permanentSessionError(connectionErr) {
			return connectionErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(options.ReconnectDelay):
		}
	}
}
