package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/novakiosk/agent/enrollment"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func rotateIdentity(args []string) {
	flags := flag.NewFlagSet("rotate", flag.ExitOnError)
	stateDir := flags.String("state-dir", "/var/lib/novakiosk-agentd", "private authority state directory")
	selection := flags.String("identity-backing", "auto", "replacement backing: auto, tpm, or software")
	ca := flags.String("ca", "", "optional trusted CA PEM")
	_ = flags.Parse(args)
	if flags.NArg() != 0 || os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "run attended rotation as the unprivileged identity owner with agentd stopped")
		os.Exit(2)
	}
	backing := ""
	if *selection != "auto" {
		var err error
		backing, err = enrollment.SelectFreshBacking(*selection)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 2*time.Minute)
	defer timeout()
	if err := (enrollment.Client{StateDir: *stateDir, CAPath: *ca}).RotateIdentity(ctx, backing); err != nil {
		fmt.Fprintf(os.Stderr, "rotation stopped; retain state and retry this attended command after resolving the error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Identity rotation activated. Restart novakiosk-agentd.service to resume managed operation.")
}
