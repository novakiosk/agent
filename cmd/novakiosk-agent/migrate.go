package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/novakiosk/agent/enrollment"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

func migrateLegacy(args []string) {
	flags := flag.NewFlagSet("migrate-legacy", flag.ExitOnError)
	instance := flags.String("instance", "", "operator-selected canonical HTTPS origin")
	profile := flags.String("profile", "", "legacy profile: kiosk or print-bridge")
	_ = flags.Parse(args)
	if *instance == "" || os.Geteuid() != 0 || flags.NArg() != 0 || (*profile != "kiosk" && *profile != "print-bridge") {
		fmt.Fprintln(os.Stderr, "attended root migration requires --instance HTTPS_ORIGIN --profile kiosk|print-bridge and stopped legacy/authority services")
		os.Exit(2)
	}
	sourceAccount := "kiosk"
	if *profile == "print-bridge" {
		sourceAccount = "novakiosk-print-bridge"
	}
	sourceUID, err := accountUID(sourceAccount)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	target, err := user.Lookup("novakiosk-agent")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	targetUID, err := strconv.ParseUint(target.Uid, 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	targetGID, err := strconv.ParseUint(target.Gid, 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	unit := "novakiosk-print-bridge.service"
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", unit)
	if *profile == "kiosk" {
		runtimeDir := "/run/user/" + strconv.FormatUint(uint64(sourceUID), 10)
		command = exec.CommandContext(ctx, "/usr/sbin/runuser", "-u", "kiosk", "--", "/usr/bin/env", "XDG_RUNTIME_DIR="+runtimeDir, "DBUS_SESSION_BUS_ADDRESS=unix:path="+runtimeDir+"/bus", "/usr/bin/systemctl", "--user", "is-active", "novakiosk-agent.service")
	}
	output, err := command.Output()
	state := strings.TrimSpace(string(output))
	if state != "inactive" && state != "failed" {
		fmt.Fprintf(os.Stderr, "stop the fixed legacy service and verify it is inactive before migration (service query: %s, %v)\n", state, err)
		os.Exit(1)
	}
	if err := enrollment.MigrateLegacyAuthority(*profile, *instance, sourceUID, uint32(targetUID), uint32(targetGID)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Legacy authority copied with a mandatory rotation marker. Keep services stopped and run rotate as novakiosk-agent; the old kiosk-readable key is not yet isolated.")
}
