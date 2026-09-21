package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/novakiosk/agent/printer"
)

const (
	printerProbeDefaultWait = 10 * time.Second
	printerProbeMaxWait     = 30 * time.Second
)

type printerProbeCollector interface {
	Collect(context.Context) (printer.Report, error)
}

func printerProbe(args []string) {
	if err := runPrinterProbe(args, printer.NewProbe(printer.Config{OptionsPath: "/usr/bin/lpoptions"}), os.Stdout); err != nil {
		// The printer package already redacts command failures into report
		// evidence.  Keep CLI diagnostics fixed as well: no raw command output
		// or stderr can escape through an internal error string.
		fmt.Fprintln(os.Stderr, "printer probe failed")
		os.Exit(1)
	}
}

// runPrinterProbe writes one bounded, validated report without mutation flags.
func runPrinterProbe(args []string, collector printerProbeCollector, output io.Writer) error {
	if collector == nil {
		return errors.New("printer probe collector is required")
	}
	if output == nil {
		return errors.New("printer probe output is required")
	}
	flags := flag.NewFlagSet("printer-probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	wait := flags.Duration("wait", printerProbeDefaultWait, "bounded probe wait")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid printer-probe flags")
	}
	if flags.NArg() != 0 {
		return errors.New("printer-probe accepts only --wait")
	}
	if *wait <= 0 || *wait > printerProbeMaxWait {
		return fmt.Errorf("--wait must be positive and no greater than %s", printerProbeMaxWait)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	report, err := collector.Collect(ctx)
	if err != nil {
		return errors.New("printer probe collection failed")
	}
	encoded, err := printer.Marshal(report)
	if err != nil {
		return errors.New("printer probe report validation failed")
	}
	if len(encoded) >= printer.MaxReportBytes {
		return errors.New("printer probe report validation failed")
	}
	line := append(encoded, '\n')
	written, err := output.Write(line)
	if err != nil || written != len(line) {
		return errors.New("printer probe output failed")
	}
	return nil
}
