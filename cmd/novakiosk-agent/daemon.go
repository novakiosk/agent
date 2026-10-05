package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/novakiosk/agent/cupsjob"
	"github.com/novakiosk/agent/cupsreconcile"
	"github.com/novakiosk/agent/enrollment"
	"github.com/novakiosk/agent/operations"
	"github.com/novakiosk/agent/printer"
	"github.com/novakiosk/agent/runtimeipc"
)

func accountUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	number, err := strconv.ParseUint(account.Uid, 10, 32)
	return uint32(number), err
}

func agentDaemon(args []string) {
	flags := flag.NewFlagSet("agentd", flag.ExitOnError)
	stateDir := flags.String("state-dir", "/var/lib/novakiosk-agentd", "private daemon state")
	socket := flags.String("socket", "/run/novakiosk-agentd/companion.sock", "daemon-owned graphical socket")
	runtimeUser := flags.String("runtime-user", "kiosk", "exact graphical peer account")
	ca := flags.String("ca", "", "optional trusted CA PEM")
	_ = flags.Parse(args)
	if os.Geteuid() == 0 || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "agentd requires a dedicated unprivileged UID distinct from the graphical account")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for ctx.Err() == nil {
		// No instance or managed authority means no socket and no outbound network.
		state, err := enrollment.LoadState(*stateDir)
		if errors.Is(err, enrollment.ErrUnconfigured) || (err == nil && state.Status != "Managed") {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentd state: %v\n", err)
			os.Exit(78)
		}
		lock, err := enrollment.AcquireAuthorityLock(*stateDir)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		err = runDaemonAuthority(ctx, *stateDir, *socket, *ca, *runtimeUser, state)
		lock.Close()
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "agentd stopped: %v\n", err)
			if errors.Is(err, enrollment.ErrIdentity) || errors.Is(err, enrollment.ErrUnconfigured) {
				os.Exit(78)
			}
			os.Exit(1)
		}
	}
}

func runDaemonAuthority(ctx context.Context, stateDir, socket, ca string, runtimeUser string, expected enrollment.State) error {
	if err := enrollment.RequireOrdinaryAuthority(stateDir); err != nil {
		return err
	}
	state, err := enrollment.LoadState(stateDir)
	if err != nil {
		return err
	}
	if state.Status != "Managed" || state.PublicIdentityRef != expected.PublicIdentityRef || state.EnrollmentID != expected.EnrollmentID {
		return fmt.Errorf("managed authority changed before lock")
	}
	identity, err := enrollment.InspectIdentity(stateDir)
	if err != nil {
		return err
	}
	if identity.DeviceID != state.DeviceID || identity.PublicIdentityRef != state.PublicIdentityRef {
		return fmt.Errorf("%w: identity state mismatch", enrollment.ErrIdentity)
	}
	if _, err := enrollment.CanonicalInstanceURL(state.InstanceURL); err != nil {
		return err
	}
	client := enrollment.Client{StateDir: stateDir, CAPath: ca, PrinterReconcileSupported: true, PrinterStatisticsSupported: true, PrinterJobsSupported: true, PrinterJobCancelSupported: true, PrinterQueueControlSupported: true}
	profile := "kiosk"
	if enrollment.EffectiveDeviceKind(state.DeviceKind) == enrollment.DeviceKindPrintServer {
		profile = "print-bridge"
	}
	helperDir, _, ok := cupsreconcile.ProfilePaths(profile)
	if !ok {
		return fmt.Errorf("invalid helper profile")
	}
	reconcile := cupsreconcile.Reconciler{StateDir: helperDir, Profile: profile}
	control := cupsjob.CancelClient{StateDir: helperDir, Profile: profile}
	report := printer.NewProbe(printer.Config{OptionsPath: "/usr/bin/lpoptions", USBSysfsRoot: "/sys/bus/usb/devices"})
	statistics := printer.NewStatisticsProbe(printer.StatisticsConfig{})
	jobs := printer.NewJobsProbe(printer.JobsConfig{})
	if profile == "print-bridge" {
		return client.PrintBridge(ctx, enrollment.PrintBridgeOptions{PrinterReporter: report, PrinterStatisticsReporter: statistics, PrinterJobsReporter: jobs, PrinterJobCanceler: control, PrinterQueueController: control, PrinterReconciler: reconcile})
	}
	runtimeUID, err := accountUID(runtimeUser)
	if err != nil || runtimeUID == uint32(os.Geteuid()) {
		return fmt.Errorf("%w: graphical account must have a distinct UID", enrollment.ErrIdentity)
	}
	server, err := runtimeipc.Listen(socket, runtimeUID, runtimeipc.Binding{EnrollmentID: state.EnrollmentID, IdentityBindingID: state.IdentityBindingID, DeviceID: state.DeviceID, KeyGeneration: identity.Generation})
	if err != nil {
		return err
	}
	defer server.Close()
	adapter := &runtimeipc.Adapter{Server: server, Origin: state.InstanceURL}
	remote, err := enrollment.NewRemoteDesktopManager(enrollment.RemoteDesktopManagerOptions{StateDir: stateDir, InstanceURL: state.InstanceURL, CAPath: ca, LocalStart: adapter.StartWayVNC})
	if err != nil {
		return err
	}
	client.IdleScreenSupported = true
	client.RemoteDesktopSupported = true
	client.BrowserSupported = true
	client.FleetUpdateSupported = operations.FleetUpdateSupported()
	return client.Run(ctx, enrollment.RunOptions{FleetSystem: &operations.LinuxFleetSystem{AgentVersion: version}, RuntimeMode: "sway", RuntimeApplier: adapter, IdleRuntime: adapter.Idle(), ManagedBrowserFactory: adapter.Browser, RuntimeSnapshot: adapter.Snapshot, RuntimeEpoch: adapter.Epoch, PrinterReporter: report, PrinterStatisticsReporter: statistics, PrinterJobsReporter: jobs, PrinterJobCanceler: control, PrinterQueueController: control, PrinterReconciler: runtimeipc.Reconciler{Reconciler: reconcile, Adapter: adapter}, RemoteDesktop: remote})
}

func graphicalRuntime(args []string) {
	flags := flag.NewFlagSet("runtime", flag.ExitOnError)
	stateDir := flags.String("state-dir", "/var/lib/novakiosk-runtime", "private graphical runtime state")
	socket := flags.String("socket", "/run/novakiosk-agentd/companion.sock", "graphical socket")
	daemonUser := flags.String("daemon-user", "novakiosk-agent", "exact daemon account")
	ca := flags.String("ca", "", "optional trusted CA PEM for public idle assets")
	_ = flags.Parse(args)
	uid, err := accountUID(*daemonUser)
	if err != nil || uid == uint32(os.Geteuid()) || os.Geteuid() == 0 || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "runtime requires a distinct unprivileged daemon UID")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := enrollment.WaitForGraphicalRuntime(ctx); err != nil {
		return
	}
	applier, err := enrollment.NewSwayRuntimeApplier(enrollment.RuntimeApplierOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	agentBinary, _ := os.Executable()
	handler := &runtimeipc.Handler{Runtime: applier, Default: cupsreconcile.Reconciler{Profile: "kiosk"}, BrowserFactory: func(ctx, lifetime context.Context, management *enrollment.RuntimeBrowserManagement) (enrollment.Browser, error) {
		options := enrollment.ChromiumOptions{LifecycleContext: lifetime, UserDataDir: *stateDir + "/browser", RequireGraphicalSession: true}
		if management != nil {
			options.KioskConfigured = true
			options.Kiosk = management.Kiosk
			options.KioskPrinting = management.KioskPrinting
		}
		return enrollment.NewChromiumBrowser(ctx, options)
	}, IdleFactory: func(lifetime context.Context, origin string) (enrollment.IdleRuntime, error) {
		return enrollment.NewSwayIdleRuntime(enrollment.IdleRuntimeOptions{LifecycleContext: lifetime, StateDir: *stateDir, InstanceURL: origin, CAPath: *ca, AgentBinary: agentBinary})
	}, WayVNC: func(ctx context.Context, session enrollment.WayVNCSession) (enrollment.RemoteDesktopProcess, error) {
		return enrollment.StartWayVNC(ctx, enrollment.RemoteDesktopManagerOptions{StateDir: *stateDir}, session)
	}}
	if err := runtimeipc.Run(ctx, *socket, uid, handler); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
