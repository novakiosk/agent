package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/novakiosk/agent/printer"
)

type fakePrinterProbeCollector struct {
	report printer.Report
	err    error
	seen   context.Context
	block  bool
}

func (f *fakePrinterProbeCollector) Collect(ctx context.Context) (printer.Report, error) {
	f.seen = ctx
	if f.block {
		<-ctx.Done()
		return f.report, nil
	}
	return f.report, f.err
}

func probeReport(transport printer.TransportState, category *printer.ErrorCategory) printer.Report {
	return printer.Report{
		Version:       printer.Version,
		Type:          printer.Type,
		Source:        printer.Source,
		ObservedAt:    "2026-08-24T12:34:56Z",
		Scheduler:     printer.SchedulerUnknown,
		Transport:     transport,
		ErrorCategory: category,
		Queues:        []printer.QueueReport{},
	}
}

func TestRunPrinterProbeWritesOneBoundedJSONReport(t *testing.T) {
	queue := printer.QueueReport{
		Name:          "label",
		QueueState:    printer.QueueIdle,
		AcceptingJobs: printer.AcceptingYes,
		PhysicalState: printer.PhysicalUnknown,
		SampledAt:     "2026-08-24T12:34:56Z",
	}
	report := probeReport(printer.TransportReachable, nil)
	report.Scheduler = printer.SchedulerRunning
	report.Queues = []printer.QueueReport{queue}
	collector := &fakePrinterProbeCollector{report: report}
	var output bytes.Buffer
	if err := runPrinterProbe([]string{"--wait", "1s"}, collector, &output); err != nil {
		t.Fatalf("runPrinterProbe: %v", err)
	}
	if output.Len() >= printer.MaxReportBytes || !strings.HasSuffix(output.String(), "\n") || strings.Count(output.String(), "\n") != 1 {
		t.Fatalf("output is not one bounded JSON line: %q", output.String())
	}
	var decoded printer.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if decoded.Scheduler != printer.SchedulerRunning || decoded.Transport != printer.TransportReachable || len(decoded.Queues) != 1 || decoded.Queues[0].PhysicalState != printer.PhysicalUnknown {
		t.Fatalf("decoded report = %#v", decoded)
	}
}

func TestRunPrinterProbeUnavailableEvidenceIsSuccess(t *testing.T) {
	category := printer.ErrorOutputLimit
	collector := &fakePrinterProbeCollector{report: probeReport(printer.TransportUnavailable, &category)}
	var output bytes.Buffer
	if err := runPrinterProbe(nil, collector, &output); err != nil {
		t.Fatalf("unavailable evidence returned error: %v", err)
	}
	var decoded printer.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if decoded.Transport != printer.TransportUnavailable || decoded.ErrorCategory == nil || *decoded.ErrorCategory != printer.ErrorOutputLimit {
		t.Fatalf("decoded unavailable report = %#v", decoded)
	}
}

func TestRunPrinterProbeUSBPermissionEvidenceIsSuccess(t *testing.T) {
	zero := 0
	category := printer.PhysicalErrorZebraUSBPermission
	report := probeReport(printer.TransportReachable, nil)
	report.Scheduler = printer.SchedulerRunning
	report.Queues = []printer.QueueReport{{Name: "zebra_usb", QueueState: printer.QueueIdle, AcceptingJobs: printer.AcceptingYes, ActiveJobs: &zero, PhysicalState: printer.PhysicalUnknown, SampledAt: "2026-08-24T12:34:56Z", DeviceTransport: printer.DeviceTransportUSB, PhysicalSource: printer.PhysicalSourceZebraUSB, PhysicalErrorCategory: &category}}
	collector := &fakePrinterProbeCollector{report: report}
	var output bytes.Buffer
	if err := runPrinterProbe(nil, collector, &output); err != nil {
		t.Fatalf("USB permission evidence returned error: %v", err)
	}
	var decoded printer.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode USB permission report: %v", err)
	}
	if decoded.Queues[0].PhysicalErrorCategory == nil || *decoded.Queues[0].PhysicalErrorCategory != printer.PhysicalErrorZebraUSBPermission {
		t.Fatalf("decoded USB permission report = %#v", decoded)
	}
}

func TestRunPrinterProbeRejectsInvalidWaitAndFlags(t *testing.T) {
	collector := &fakePrinterProbeCollector{report: probeReport(printer.TransportReachable, nil)}
	for _, args := range [][]string{
		{"--wait", "0s"},
		{"--wait", "31s"},
		{"--wait", "-1s"},
		{"--path", "/tmp/lpstat"},
		{"queue-name"},
	} {
		var output bytes.Buffer
		if err := runPrinterProbe(args, collector, &output); err == nil {
			t.Fatalf("args %v unexpectedly accepted", args)
		}
		if output.Len() != 0 {
			t.Fatalf("args %v wrote output on error: %q", args, output.String())
		}
	}
}

func TestRunPrinterProbeBoundsContextAndPreservesTimeoutEvidence(t *testing.T) {
	category := printer.ErrorTimeout
	collector := &fakePrinterProbeCollector{
		report: probeReport(printer.TransportTimeout, &category),
		block:  true,
	}
	var output bytes.Buffer
	started := time.Now()
	if err := runPrinterProbe([]string{"--wait", "25ms"}, collector, &output); err != nil {
		t.Fatalf("timeout evidence returned error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("probe exceeded bounded wait: %s", elapsed)
	}
	if collector.seen == nil {
		t.Fatal("collector did not receive context")
	}
	deadline, ok := collector.seen.Deadline()
	if !ok || time.Until(deadline) > 100*time.Millisecond {
		t.Fatalf("collector deadline missing or too far away: %v, %v", deadline, ok)
	}
	var decoded printer.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode timeout report: %v", err)
	}
	if decoded.Transport != printer.TransportTimeout {
		t.Fatalf("decoded timeout report = %#v", decoded)
	}
}

func TestRunPrinterProbeRedactsCollectorErrors(t *testing.T) {
	collector := &fakePrinterProbeCollector{err: errors.New("SENSITIVE-STDERR raw lpstat output")}
	var output bytes.Buffer
	err := runPrinterProbe(nil, collector, &output)
	if err == nil || strings.Contains(err.Error(), "SENSITIVE-STDERR") || strings.Contains(output.String(), "SENSITIVE-STDERR") {
		t.Fatalf("raw collector diagnostic leaked: err=%v output=%q", err, output.String())
	}
}

func TestRunPrinterProbeRejectsInvalidCollectorReport(t *testing.T) {
	collector := &fakePrinterProbeCollector{report: printer.Report{Version: printer.Version}}
	var output bytes.Buffer
	if err := runPrinterProbe(nil, collector, &output); err == nil {
		t.Fatal("invalid report unexpectedly accepted")
	}
	if output.Len() != 0 {
		t.Fatalf("invalid report wrote output: %q", output.String())
	}
}
