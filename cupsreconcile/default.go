package cupsreconcile

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/novakiosk/agent/cupsjob"
)

// MaintainDefault runs as the kiosk account. User CUPS defaults take precedence
// over the server default, and are read by Chromium on each print preview.
// Selection comes from desired membership, never transient physical health.
func (reconciler Reconciler) MaintainDefault(ctx context.Context, desired Desired) error {
	if reconciler.Profile != "kiosk" || desired.Validate() != nil {
		return errors.New("invalid printer default")
	}
	if desired.DefaultQueue == nil || *desired.DefaultQueue == "" {
		return nil
	}
	selected := *desired.DefaultQueue
	var queue Queue
	for _, candidate := range desired.Queues {
		if candidate.LocalName == selected {
			queue = candidate
			break
		}
	}
	runner := reconciler.DefaultRunner
	if runner == nil {
		runner = cupsjob.ExecRunner{}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("printer default home unavailable")
	}
	env := []string{"HOME=" + home}
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Validate the local destination without touching or probing the device.
	output, _, err := runner.Run(commandCtx, "/usr/bin/lpstat", []string{"-v", selected}, env)
	if err != nil {
		return errors.New("printer default queue unavailable")
	}
	line := strings.TrimSpace(string(output))
	prefix := "device for " + selected + ": "
	if !strings.HasPrefix(line, prefix) || strings.ContainsAny(line, "\r\n") {
		return errors.New("printer default queue invalid")
	}
	uri := strings.TrimPrefix(line, prefix)
	if queue.Mode == ModeRemote && uri != queue.RemoteURI || queue.Mode == ModeExisting && !strings.HasPrefix(uri, "usb://") {
		return errors.New("printer default queue mismatch")
	}
	output, _, err = runner.Run(commandCtx, "/usr/bin/lpstat", []string{"-d"}, env)
	if err != nil {
		return errors.New("printer default read failed")
	}
	if strings.TrimSpace(string(output)) == "system default destination: "+selected {
		return nil
	}
	if _, _, err = runner.Run(commandCtx, "/usr/bin/lpoptions", []string{"-d", selected}, env); err != nil {
		return errors.New("printer default update failed")
	}
	output, _, err = runner.Run(commandCtx, "/usr/bin/lpstat", []string{"-d"}, env)
	if err != nil || strings.TrimSpace(string(output)) != "system default destination: "+selected {
		return errors.New("printer default postcheck failed")
	}
	return nil
}
