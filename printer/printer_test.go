package printer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type commandResult struct {
	stdout string
	stderr string
	err    error
}

type recordingRunner struct {
	mu       sync.Mutex
	results  map[string]commandResult
	argv     [][]string
	paths    []string
	envs     [][]string
	contexts []context.Context
}

type recordingUSBProber struct {
	serials  []string
	response []byte
	category PhysicalErrorCategory
}

func (p *recordingUSBProber) ProbeZebraHostStatus(_ context.Context, serial string, _ time.Duration) ([]byte, PhysicalErrorCategory) {
	p.serials = append(p.serials, serial)
	return append([]byte(nil), p.response...), p.category
}

func (r *recordingRunner) Run(ctx context.Context, path string, args []string, env []string) ([]byte, []byte, error) {
	r.mu.Lock()
	r.argv = append(r.argv, append([]string(nil), args...))
	r.paths = append(r.paths, path)
	r.envs = append(r.envs, append([]string(nil), env...))
	r.contexts = append(r.contexts, ctx)
	r.mu.Unlock()
	key := strings.Join(args, " ")
	result, ok := r.results[key]
	if !ok {
		return nil, nil, errors.New("unexpected command")
	}
	return []byte(result.stdout), []byte(result.stderr), result.err
}

func fixedClock() time.Time {
	return time.Date(2026, time.August, 24, 12, 34, 56, 123000000, time.UTC)
}

func testProbe(r Runner) *Probe {
	return NewProbe(Config{
		Runner:           r,
		Clock:            fixedClock,
		Path:             "/test/lpstat",
		CommandTimeout:   time.Second,
		AggregateTimeout: 10 * time.Second,
		MaxStdoutBytes:   4096,
		MaxStderrBytes:   1024,
	})
}

func TestProbeExactArgvEnvAndPhysicalUnknown(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		"-r":                        {stdout: "scheduler is running\n"},
		"-e":                        {stdout: "zebra\nalpha\nzebra\n"},
		"-v":                        {stdout: "device for alpha: usb://Zebra/alpha\ndevice for zebra: ipp://printer.example/queue\n"},
		"-l -p alpha":               {stdout: "printer alpha is idle.\n"},
		"-a alpha":                  {stdout: "alpha accepting requests since Mon 01 Jan 2024 00:00:00\n"},
		"-W not-completed -o alpha": {stdout: ""},
		"-v alpha":                  {stdout: "device for alpha: usb://Zebra/alpha\n"},
		"-l -p zebra":               {stdout: "printer zebra now printing zebra-14.\n"},
		"-a zebra":                  {stdout: "zebra not accepting requests since Mon 01 Jan 2024 00:00:00\n"},
		"-W not-completed -o zebra": {stdout: "zebra-1 owner 1\nzebra-2 owner 2\n"},
		"-v zebra":                  {stdout: "device for zebra: ipp://printer.example/queue\n"},
	}}
	report, err := testProbe(runner).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if report.Scheduler != SchedulerRunning || report.Transport != TransportReachable {
		t.Fatalf("unexpected top-level state: %#v", report)
	}
	if len(report.Queues) != 2 || report.Queues[0].Name != "alpha" || report.Queues[1].Name != "zebra" {
		t.Fatalf("queues were not deduplicated/sorted: %#v", report.Queues)
	}
	if report.Queues[0].QueueState != QueueIdle || report.Queues[0].AcceptingJobs != AcceptingYes || report.Queues[0].ActiveJobs == nil || *report.Queues[0].ActiveJobs != 0 {
		t.Fatalf("alpha evidence: %#v", report.Queues[0])
	}
	if report.Queues[1].QueueState != QueueProcessing || report.Queues[1].AcceptingJobs != AcceptingNo || report.Queues[1].ActiveJobs == nil || *report.Queues[1].ActiveJobs != 2 {
		t.Fatalf("zebra evidence: %#v", report.Queues[1])
	}
	for _, queue := range report.Queues {
		if queue.PhysicalState != PhysicalUnknown {
			t.Fatalf("physical state inferred: %#v", queue)
		}
	}
	if err := Validate(report); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	wantArgs := [][]string{
		{"-r"}, {"-e"}, {"-v"}, {"-l", "-p", "alpha"}, {"-a", "alpha"}, {"-W", "not-completed", "-o", "alpha"},
		{"-l", "-p", "zebra"}, {"-a", "zebra"}, {"-W", "not-completed", "-o", "zebra"},
	}
	if !reflect.DeepEqual(runner.argv, wantArgs) {
		t.Fatalf("argv = %#v, want %#v", runner.argv, wantArgs)
	}
	for index, path := range runner.paths {
		if path != "/test/lpstat" {
			t.Fatalf("path[%d] = %q", index, path)
		}
		if !reflect.DeepEqual(runner.envs[index], []string{"LC_ALL=C", "LANG=C"}) {
			t.Fatalf("env[%d] = %#v", index, runner.envs[index])
		}
		if _, ok := runner.contexts[index].Deadline(); !ok {
			t.Fatalf("command %d has no timeout", index)
		}
	}
}

func TestSchedulerFailureCategories(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		category  ErrorCategory
		transport TransportState
	}{
		{name: "missing", err: exec.ErrNotFound, category: ErrorBinaryMissing, transport: TransportUnavailable},
		{name: "stopped", err: errors.New("lpstat exited 1"), category: ErrorCommandFailed, transport: TransportUnavailable},
		{name: "timeout", err: context.DeadlineExceeded, category: ErrorTimeout, transport: TransportTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingRunner{results: map[string]commandResult{"-r": {err: tt.err}}}
			report, err := testProbe(runner).Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if report.Scheduler != SchedulerUnknown || report.Transport != tt.transport || report.ErrorCategory == nil || *report.ErrorCategory != tt.category {
				t.Fatalf("report = %#v", report)
			}
			if len(runner.argv) != 1 || !reflect.DeepEqual(runner.argv[0], []string{"-r"}) {
				t.Fatalf("unexpected follow-on commands: %#v", runner.argv)
			}
		})
	}

	runner := &recordingRunner{results: map[string]commandResult{
		"-r": {stdout: "scheduler is not running\n"},
		"-e": {stdout: ""},
	}}
	report, err := testProbe(runner).Collect(context.Background())
	if err != nil || report.Scheduler != SchedulerStopped || report.Transport != TransportReachable || report.ErrorCategory != nil {
		t.Fatalf("stopped scheduler report = %#v, err=%v", report, err)
	}

	// lpstat can emit the explicit stopped sentence while exiting nonzero;
	// that remains reachable scheduler evidence and must not be collapsed into
	// an unavailable transport.
	runner = &recordingRunner{results: map[string]commandResult{
		"-r": {stdout: "scheduler is not running\n", stderr: "raw scheduler diagnostic\n", err: errors.New("exit status 1")},
		"-e": {stdout: ""},
	}}
	report, err = testProbe(runner).Collect(context.Background())
	if err != nil || report.Scheduler != SchedulerStopped || report.Transport != TransportReachable || report.ErrorCategory != nil {
		t.Fatalf("nonzero stopped scheduler report = %#v, err=%v", report, err)
	}
}

func TestConservativeParsers(t *testing.T) {
	if got := ParseSchedulerOutput([]byte("scheduler is not running\n")); got != SchedulerStopped {
		t.Fatalf("scheduler stopped = %q", got)
	}
	if got := ParseSchedulerOutput([]byte("scheduler is running\n")); got != SchedulerRunning {
		t.Fatalf("scheduler running = %q", got)
	}
	if got := ParseSchedulerOutput([]byte("scheduler maybe running\n")); got != SchedulerUnknown {
		t.Fatalf("scheduler unknown = %q", got)
	}

	for _, tt := range []struct {
		output string
		want   QueueState
	}{
		{"printer q is idle.\n", QueueIdle},
		{"printer q now printing q-1.\n", QueueProcessing},
		{"printer q disabled since Mon\n", QueueStopped},
		{"printer q strange state\n", QueueUnknown},
		{"printer other is idle.\n", QueueUnknown},
	} {
		if got := ParseQueueState("q", []byte(tt.output)); got != tt.want {
			t.Errorf("ParseQueueState(%q) = %q, want %q", tt.output, got, tt.want)
		}
	}
	if got := ParseQueueState("q", []byte("printer q is idle. enabled since Mon\n  backend diagnostic\n")); got != QueueIdle {
		t.Fatalf("multiline queue status = %q", got)
	}
	if got := ParseQueueState("q", []byte("printer q is idle.\nprinter q is stopped.\n")); got != QueueUnknown {
		t.Fatalf("conflicting queue status = %q", got)
	}
	for _, tt := range []struct {
		output string
		want   DeviceTransport
	}{
		{"device for q: usb://Zebra%20ZD421\n", DeviceTransportUSB},
		{"device for q: ipp://printer.example/queue\n", DeviceTransportNetwork},
		{"device for q: dnssd://printer.example\n", DeviceTransportNetwork},
		{"device for q: implicitclass://q/\n", DeviceTransportNetwork},
		{"device for q: secret://host/value\n", DeviceTransportUnknown},
	} {
		if got := ParseDeviceTransport("q", []byte(tt.output)); got != tt.want {
			t.Errorf("ParseDeviceTransport(%q) = %q, want %q", tt.output, got, tt.want)
		}
	}
	if got := ParseAcceptingJobs("q", []byte("q accepting requests since Mon\n")); got != AcceptingYes {
		t.Fatalf("accepting yes = %q", got)
	}
	if got := ParseAcceptingJobs("q", []byte("q not accepting requests since Mon\n")); got != AcceptingNo {
		t.Fatalf("accepting no = %q", got)
	}
	if got := ParseAcceptingJobs("q", []byte("q accepting maybe\n")); got != AcceptingUnknown {
		t.Fatalf("accepting unknown = %q", got)
	}
	if got := ParseActiveJobs("q", nil); got == nil || *got != 0 {
		t.Fatalf("empty jobs = %#v", got)
	}
	if got := ParseActiveJobs("q", []byte("q-1 owner title\nq-22 owner title\n")); got == nil || *got != 2 {
		t.Fatalf("multiple jobs = %#v", got)
	}
	if got := ParseActiveJobs("q", []byte("q-1 owner\nmalicious\n")); got != nil {
		t.Fatalf("malformed jobs = %#v", got)
	}
}

func TestDeviceTransportSnapshotStrictMapping(t *testing.T) {
	queues := []string{"alpha", "usb-late"}
	snapshot := "device for alpha: ipp://printer.example/alpha\n" +
		"device for usb-late: usb://Zebra/model\n"
	evidence, complete := parseDeviceTransportSnapshot([]byte(snapshot), queues)
	if !complete || evidence["alpha"].transport != DeviceTransportNetwork || evidence["usb-late"].transport != DeviceTransportUSB {
		t.Fatalf("complete snapshot = %v, evidence = %#v", complete, evidence)
	}
	if strings.Contains(string(evidence["usb-late"].line), "usb://") == false {
		t.Fatal("process-local evidence did not retain the line needed by the physical probe")
	}

	for _, tt := range []struct {
		name   string
		output string
		want   map[string]DeviceTransport
	}{
		{
			name:   "duplicate queue",
			output: "device for alpha: ipp://printer.example/alpha\ndevice for alpha: usb://Zebra/model\ndevice for usb-late: usb://Zebra/model\n",
			want:   map[string]DeviceTransport{"usb-late": DeviceTransportUSB},
		},
		{
			name:   "unknown queue",
			output: "device for stale: ipp://printer.example/stale\ndevice for alpha: ipp://printer.example/alpha\ndevice for usb-late: usb://Zebra/model\n",
			want:   map[string]DeviceTransport{"alpha": DeviceTransportNetwork, "usb-late": DeviceTransportUSB},
		},
		{
			name:   "malformed line",
			output: "device for alpha: ipp://printer.example/alpha\nnot a device line\ndevice for usb-late: usb://Zebra/model\n",
			want:   map[string]DeviceTransport{"alpha": DeviceTransportNetwork, "usb-late": DeviceTransportUSB},
		},
		{
			name:   "URI whitespace",
			output: "device for alpha: ipp://printer.example/alpha queue\ndevice for usb-late: usb://Zebra/model\n",
			want:   map[string]DeviceTransport{"usb-late": DeviceTransportUSB},
		},
		{
			name:   "URI control character",
			output: "device for alpha: ipp://printer.example/alpha\x00queue\ndevice for usb-late: usb://Zebra/model\n",
			want:   map[string]DeviceTransport{"usb-late": DeviceTransportUSB},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			evidence, complete := parseDeviceTransportSnapshot([]byte(tt.output), queues)
			if complete {
				t.Fatal("invalid snapshot was marked complete")
			}
			if len(evidence) != len(tt.want) {
				t.Fatalf("evidence = %#v, want %#v", evidence, tt.want)
			}
			for name, transport := range tt.want {
				if evidence[name].transport != transport {
					t.Fatalf("%s transport = %q, want %q", name, evidence[name].transport, transport)
				}
			}
		})
	}
}

func TestParseQueueOptionsBoundsExactZebraEvidence(t *testing.T) {
	output := []byte("PageSize/Media Size: 2x1 *4x6 Custom.WIDTHxHEIGHT\nMediaType/Media Type: Saved Thermal Direct\nColorModel/Print Color Mode: *Gray\nprint-scaling/Print Scaling: *auto fit none\nBad Option: *value\nPageSize/Duplicate: *A4\n")
	wantGray := "Gray"
	wantAuto := "auto"
	wantPage := "4x6"
	want := []QueueOption{
		{Name: "ColorModel", Default: &wantGray, Choices: []string{"Gray"}},
		{Name: "MediaType", Choices: []string{"Saved", "Thermal", "Direct"}},
		{Name: "PageSize", Default: &wantPage, Choices: []string{"2x1", "4x6", "Custom.WIDTHxHEIGHT"}},
		{Name: "print-scaling", Default: &wantAuto, Choices: []string{"auto", "fit", "none"}},
	}
	if got := ParseQueueOptions(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("options = %#v, want %#v", got, want)
	}
	zero := 0
	report := Report{Version: Version, Type: Type, Source: Source, ObservedAt: fixedClock().Format(time.RFC3339Nano), Scheduler: SchedulerRunning, Transport: TransportReachable, Queues: []QueueReport{{Name: "zebra", QueueState: QueueIdle, AcceptingJobs: AcceptingYes, ActiveJobs: &zero, PhysicalState: PhysicalUnknown, SampledAt: fixedClock().Format(time.RFC3339Nano), Options: want}}}
	if err := Validate(report); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalPayload(report)
	if err != nil || !strings.Contains(string(canonical), "\toptions=") {
		t.Fatalf("canonical options binding missing: %v %q", err, canonical)
	}
}

func TestParseVariablePaperBoundsFromInstalledZebraPPD(t *testing.T) {
	ppd := []byte("*CustomPageSize True\n*DefaultPageSize: Custom.90x70mm\n*ParamCustomPageSize Width: 1 points 36 576\n*ParamCustomPageSize Height: 2 points 36 3600\n")
	bounds, ok := ParseVariablePaperBounds(ppd)
	if !ok {
		t.Fatal("valid generated PPD was rejected")
	}
	if bounds.MinWidthPoints != 36 || bounds.MaxWidthPoints != 576 || bounds.MinHeightPoints != 36 || bounds.MaxHeightPoints != 3600 {
		t.Fatalf("bounds = %+v", bounds)
	}
	width, height, defaultOK := parseVariablePaperDefault(ppd, bounds)
	if !defaultOK || width != 90 || height != 70 {
		t.Fatalf("default media = %gx%g, %v", width, height, defaultOK)
	}
	large := append(append([]byte(nil), ppd...), bytes.Repeat([]byte("*% padding\n"), 26_000)...)
	if _, ok := ParseVariablePaperBounds(large); !ok {
		t.Fatal("realistic generated Zebra PPD size was rejected")
	}
	if _, ok := ParseVariablePaperBounds(append(append([]byte(nil), ppd...), bytes.Repeat([]byte("*% padding\n"), MaxPPDBytes/11+1)...)); ok {
		t.Fatal("oversized PPD was accepted")
	}
	if _, ok := ParseVariablePaperBounds([]byte("*CustomPageSize True\n*ParamCustomPageSize Width: 1 points 36 576\n")); ok {
		t.Fatal("incomplete PPD bounds accepted")
	}
	if _, ok := ParseVariablePaperBounds([]byte("*ParamCustomPageSize Width: \"1\" points 36 576\n*ParamCustomPageSize True\n*ParamCustomPageSize Height: 2 points 36 3600\n")); ok {
		t.Fatal("malformed quoted PPD parameter accepted")
	}
	ppdDir := t.TempDir()
	queueName := "zebra_usb"
	if err := os.WriteFile(filepath.Join(ppdDir, queueName+".ppd"), large, 0o640); err != nil {
		t.Fatal(err)
	}
	media, ok := readQueuePPDBounds(ppdDir, queueName)
	if !ok || media.DefaultWidthMM == nil || media.DefaultHeightMM == nil || *media.DefaultWidthMM != 90 || *media.DefaultHeightMM != 70 {
		t.Fatalf("queue custom media = %+v, %v", media, ok)
	}
}

func TestZebraUSBProbeDecodesLiveHeadUpResponse(t *testing.T) {
	const response = "\x02030,0,1,0485,000,0,0,0,000,0,0,0\x03\r\n\x02000,0,1,0,0,3,5,0,00000000,1,000\x03\r\n\x020000,0\x03\r\n"
	runner := &recordingRunner{results: map[string]commandResult{
		"-r":                            {stdout: "scheduler is running\n"},
		"-e":                            {stdout: "zebra_usb\n"},
		"-v":                            {stdout: "device for zebra_usb: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=FIXTURE00001\n"},
		"-l -p zebra_usb":               {stdout: "printer zebra_usb is idle.  enabled since Tue Aug 25 11:49:02 2026\n\tPrinter types: unknown\n\tAlerts: none\n\tConnection: direct\n"},
		"-a zebra_usb":                  {stdout: "zebra_usb accepting requests since Tue\n"},
		"-W not-completed -o zebra_usb": {},
		"-v zebra_usb":                  {stdout: "device for zebra_usb: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=FIXTURE00001\n"},
	}}
	usbProber := &recordingUSBProber{response: []byte(response)}
	probe := NewProbe(Config{
		Runner: runner, Clock: fixedClock, Path: "/test/lpstat", CommandTimeout: time.Second,
		AggregateTimeout: 10 * time.Second, MaxStdoutBytes: 4096, MaxStderrBytes: 1024, USBProber: usbProber,
	})
	report, err := probe.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Queues) != 1 {
		t.Fatalf("queues = %#v", report.Queues)
	}
	queue := report.Queues[0]
	wantReasons := []PhysicalReason{PhysicalReasonPaused, PhysicalReasonHeadUp}
	if queue.QueueState != QueueIdle || queue.DeviceTransport != DeviceTransportUSB || queue.PhysicalState != PhysicalAttention || queue.PhysicalSource != PhysicalSourceZebraUSB || !reflect.DeepEqual(queue.PhysicalReasons, wantReasons) || queue.PhysicalErrorCategory != nil {
		t.Fatalf("USB physical evidence = %#v", queue)
	}
	if !reflect.DeepEqual(usbProber.serials, []string{"FIXTURE00001"}) {
		t.Fatalf("USB serials = %#v", usbProber.serials)
	}
	if err := Validate(report); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestUSBSpecificPhysicalErrorsValidateOnlyForUSBSource(t *testing.T) {
	zero := 0
	for _, category := range []PhysicalErrorCategory{PhysicalErrorZebraUSBUnavailable, PhysicalErrorZebraUSBPermission, PhysicalErrorZebraUSBBusy} {
		report := Report{Version: Version, Type: Type, Source: Source, ObservedAt: fixedClock().Format(time.RFC3339Nano), Scheduler: SchedulerRunning, Transport: TransportReachable, Queues: []QueueReport{{Name: "zebra_usb", QueueState: QueueIdle, AcceptingJobs: AcceptingYes, ActiveJobs: &zero, PhysicalState: PhysicalUnknown, SampledAt: fixedClock().Format(time.RFC3339Nano), DeviceTransport: DeviceTransportUSB, PhysicalSource: PhysicalSourceZebraUSB, PhysicalErrorCategory: physicalErrorPtr(category)}}}
		if _, err := Marshal(report); err != nil {
			t.Fatalf("USB category %q was rejected: %v", category, err)
		}
		report.Queues[0].PhysicalSource = PhysicalSourceZebraTCP
		if _, err := Marshal(report); err == nil {
			t.Fatalf("USB category %q was accepted for TCP evidence", category)
		}
	}
}

func TestZebraUSBProbeDoesNotClaimInterfaceWithActiveJob(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		"-r":                            {stdout: "scheduler is running\n"},
		"-e":                            {stdout: "zebra_usb\n"},
		"-v":                            {stdout: "device for zebra_usb: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=FIXTURE00001\n"},
		"-l -p zebra_usb":               {stdout: "printer zebra_usb is idle.\n\tAlerts: none\n"},
		"-a zebra_usb":                  {stdout: "zebra_usb accepting requests since Tue\n"},
		"-W not-completed -o zebra_usb": {stdout: "zebra_usb-1 owner title\n"},
		"-v zebra_usb":                  {stdout: "device for zebra_usb: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=FIXTURE00001\n"},
	}}
	usbProber := &recordingUSBProber{response: []byte(zebraHealthySample)}
	probe := NewProbe(Config{
		Runner: runner, Clock: fixedClock, Path: "/test/lpstat", CommandTimeout: time.Second,
		AggregateTimeout: 10 * time.Second, MaxStdoutBytes: 4096, MaxStderrBytes: 1024, USBProber: usbProber,
	})
	report, err := probe.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	queue := report.Queues[0]
	if len(usbProber.serials) != 0 || queue.PhysicalState != PhysicalUnknown || queue.PhysicalSource != PhysicalSourceCUPS {
		t.Fatalf("active-job USB evidence = %#v, calls=%#v", queue, usbProber.serials)
	}
}

func TestZebraUSBTargetEligibility(t *testing.T) {
	accepted := "device for q: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=FIXTURE00001\n"
	if serial, ok := parseZebraUSBSerial("q", []byte(accepted)); !ok || serial != "FIXTURE00001" {
		t.Fatalf("eligible USB URI = %q, %v", serial, ok)
	}
	for _, output := range []string{
		"device for q: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL\n",
		"device for q: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=../../device\n",
		"device for q: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=one&serial=two\n",
		"device for q: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=one&other=value\n",
		"device for q: usb://Other/ZTC%20ZD421-203dpi%20ZPL?serial=FIXTURE00001\n",
		"device for q: usb://Zebra%20Technologies/ZTC%20ZT411?serial=FIXTURE00001\n",
		"device for q: socket://10.0.0.12:9100\n",
	} {
		if serial, ok := parseZebraUSBSerial("q", []byte(output)); ok {
			t.Errorf("unsafe USB target accepted: %q from %q", serial, output)
		}
	}
}

const zebraHealthySample = "030,0,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,1,000\n0000,0\n"

func TestZebraStatusParserAcceptsPlainAndOfficialFraming(t *testing.T) {
	status, err := parseZebraHS([]byte(zebraHealthySample))
	if err != nil || len(zebraReasons(status)) != 0 {
		t.Fatalf("healthy Zebra sample = %#v, err=%v", status, err)
	}
	framed := []byte("\x02030,0,0,0546,000,0,0,0,000,0,0,0\x03\r\n\x02000,0,0,0,0,2,6,0,00000000,1,000\x03\r\n\x020000,0\x03\r\n")
	status, err = parseZebraHS(framed)
	if err != nil || len(zebraReasons(status)) != 0 {
		t.Fatalf("framed Zebra sample = %#v, err=%v", status, err)
	}
}

func TestZebraStatusParserDerivesAllFaultReasons(t *testing.T) {
	sample := "030,1,1,0546,002,1,1,1,000,1,1,1\n000,0,1,1,1,2,6,1,00000000,1,000\n0000,0\n"
	status, err := parseZebraHS([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []PhysicalReason{
		PhysicalReasonPaperOut, PhysicalReasonPaused, PhysicalReasonBufferFull,
		PhysicalReasonDiagnosticMode, PhysicalReasonPartialFormat, PhysicalReasonConfigurationLost,
		PhysicalReasonUnderTemperature, PhysicalReasonOverTemperature, PhysicalReasonHeadUp,
		PhysicalReasonRibbonOut,
	}
	if !reflect.DeepEqual(zebraReasons(status), want) {
		t.Fatalf("reasons = %#v, want %#v", zebraReasons(status), want)
	}
}

func TestZebraStatusParserRejectsMalformedResponses(t *testing.T) {
	cases := []string{
		"030,0\n000,0\n0000,0\n",
		"30,0,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,1,000\n0000,0\n",
		"030,0,0,0546,000,0,2,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,1,000\n0000,0\n",
		"030,x,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,1,000\n0000,0\n",
		"030,0,0,0546,000,0,0,0,000,0,0,0\n000,2,0,0,0,2,6,0,00000000,1,000\n0000,0\n",
		"030,0,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,5,6,0,00000000,1,000\n0000,0\n",
		"030,0,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,0,000\n0000,0\n",
		"030,0,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,1,000\n0000,2\n",
		"030,0,0,0546,000,0,0,0,000,0,0,0\n000,0,0,0,0,2,6,0,00000000,1,000\n0000,0\nextra\n",
		"\x02030,0,0,0546,000,0,0,0,000,0,0,0\x03\r\n000,0,0,0,0,2,6,0,00000000,1,000\r\n0000,0\r\n",
	}
	for _, sample := range cases {
		if _, err := parseZebraHS([]byte(sample)); err == nil {
			t.Fatalf("accepted malformed Zebra response %q", sample)
		}
	}
}

func TestCUPSPhysicalReasonParserIsNarrowAndMultiline(t *testing.T) {
	reasons, valid := ParseCUPSStateReasons([]byte("printer q is idle.\n\tprinter-state-reasons: media-empty,cover-open\n\tbackend diagnostic text\n"))
	if !valid || !reflect.DeepEqual(reasons, []PhysicalReason{PhysicalReasonMediaEmpty, PhysicalReasonCoverOpen}) {
		t.Fatalf("CUPS reasons = %#v, valid=%v", reasons, valid)
	}
	if reasons, valid := ParseCUPSStateReasons([]byte("printer q is idle.\nprinter-state-reasons: none\n")); !valid || len(reasons) != 0 {
		t.Fatalf("CUPS none = %#v, valid=%v", reasons, valid)
	}
	if reasons, valid := ParseCUPSStateReasons([]byte("printer-state-reasons: media-empty,unknown-reason\n")); !valid || !reflect.DeepEqual(reasons, []PhysicalReason{PhysicalReasonMediaEmpty}) {
		t.Fatalf("unknown CUPS token changed recognized evidence: %#v, valid=%v", reasons, valid)
	}
	realistic := "printer zebra_usb is idle. enabled since Tue 25 Aug 2026 12:00:00\n\tDescription: Zebra\n\tAlerts: media-empty-error com.zebra.vendor-warning cover-open-warning\n\tLocation: lab\n"
	if reasons, valid := ParseCUPSStateReasons([]byte(realistic)); !valid || !reflect.DeepEqual(reasons, []PhysicalReason{PhysicalReasonMediaEmpty, PhysicalReasonCoverOpen}) {
		t.Fatalf("realistic CUPS Alerts = %#v, valid=%v", reasons, valid)
	}
	if reasons, valid := ParseCUPSStateReasons([]byte("Alerts: none\n")); !valid || len(reasons) != 0 {
		t.Fatalf("CUPS Alerts none = %#v, valid=%v", reasons, valid)
	}
	if _, valid := ParseCUPSStateReasons([]byte("Alerts: media-empty\nprinter-state-reasons: media-empty\n")); valid {
		t.Fatal("accepted duplicate CUPS physical reason fields")
	}
	if reasons, valid := ParseCUPSStateReasons([]byte("printer q is idle.\n")); !valid || len(reasons) != 0 {
		t.Fatalf("CUPS absent reasons = %#v, valid=%v", reasons, valid)
	}
}

func TestZebraTargetEligibility(t *testing.T) {
	accepted := []string{
		"device for q: socket://10.0.0.12:9100\n",
		"device for q: socket://192.168.1.20:9100\n",
		"device for q: socket://[fd12::20]:9100\n",
		"device for q: socket://169.254.1.2:9100\n",
	}
	for _, output := range accepted {
		if target, ok := parseZebraTarget("q", []byte(output)); !ok || target == "" {
			t.Errorf("target %q rejected: %q, %v", output, target, ok)
		}
	}
	rejected := []string{
		"device for q: socket://printer.example:9100\n",
		"device for q: socket://8.8.8.8:9100\n",
		"device for q: socket://127.0.0.1:9100\n",
		"device for q: socket://0.0.0.0:9100\n",
		"device for q: socket://224.0.0.1:9100\n",
		"device for q: socket://10.0.0.12:9101\n",
		"device for q: socket://user@10.0.0.12:9100\n",
		"device for q: socket://10.0.0.12:9100/path\n",
		"device for q: ipp://10.0.0.12:9100\n",
	}
	for _, output := range rejected {
		if target, ok := parseZebraTarget("q", []byte(output)); ok {
			t.Errorf("unsafe target accepted: %q", target)
		}
	}
}

// Deliver EOF only when the probe reads, after its deadline is installed.
// Closing net.Pipe earlier can instead fail SetReadDeadline nondeterministically.
type noResponseConn struct {
	net.Conn
	peer net.Conn
}

func (connection noResponseConn) Read(data []byte) (int, error) {
	_ = connection.peer.Close()
	return connection.Conn.Read(data)
}

func (connection noResponseConn) Close() error {
	_ = connection.peer.Close()
	return connection.Conn.Close()
}

func TestZebraTCPProbeHandlesFragmentedResponseAndFailures(t *testing.T) {
	dialer := func(response []byte, noResponse bool) Dialer {
		return func(context.Context, string, string) (net.Conn, error) {
			server, client := net.Pipe()
			if noResponse {
				go func() {
					command := make([]byte, 3)
					_, _ = server.Read(command)
				}()
				return noResponseConn{Conn: client, peer: server}, nil
			}
			go func() {
				defer server.Close()
				command := make([]byte, 3)
				_, _ = server.Read(command)
				for _, chunk := range [][]byte{response[:12], response[12:37], response[37:]} {
					_, _ = server.Write(chunk)
				}
			}()
			return client, nil
		}
	}
	p := NewProbe(Config{Dialer: dialer([]byte(zebraHealthySample), false), PhysicalTimeout: time.Second})
	state, reasons, category := p.probeZebra(context.Background(), "10.0.0.12:9100")
	if state != PhysicalReady || len(reasons) != 0 || category != nil {
		t.Fatalf("fragmented probe = %q %#v %v", state, reasons, category)
	}
	p = NewProbe(Config{Dialer: dialer(nil, true), PhysicalTimeout: 100 * time.Millisecond})
	state, reasons, category = p.probeZebra(context.Background(), "10.0.0.12:9100")
	if state != PhysicalUnknown || len(reasons) != 0 || category == nil || *category != PhysicalErrorZebraNoResponse {
		t.Fatalf("no-response probe = %q %#v %v", state, reasons, category)
	}
	large := strings.Repeat("0", maxZebraResponseBytes+1)
	p = NewProbe(Config{Dialer: dialer([]byte(large), false), PhysicalTimeout: time.Second})
	state, reasons, category = p.probeZebra(context.Background(), "10.0.0.12:9100")
	if state != PhysicalUnknown || len(reasons) != 0 || category == nil || *category != PhysicalErrorZebraOversize {
		if category == nil {
			t.Fatalf("oversize probe = %q %#v <nil>", state, reasons)
		}
		t.Fatalf("oversize probe = %q %#v %q", state, reasons, *category)
	}
	p = NewProbe(Config{Dialer: func(context.Context, string, string) (net.Conn, error) {
		_, client := net.Pipe()
		return client, nil
	}, PhysicalTimeout: 25 * time.Millisecond})
	state, reasons, category = p.probeZebra(context.Background(), "10.0.0.12:9100")
	if state != PhysicalUnknown || len(reasons) != 0 || category == nil || *category != PhysicalErrorZebraTimeout {
		t.Fatalf("timeout probe = %q %#v %v", state, reasons, category)
	}
}

func TestZebraTCPProbeReturnsAfterCompleteResponseWithoutEOF(t *testing.T) {
	dialer := func(context.Context, string, string) (net.Conn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			command := make([]byte, 3)
			_, _ = io.ReadFull(server, command)
			for _, chunk := range [][]byte{[]byte(zebraHealthySample[:12]), []byte(zebraHealthySample[12:37]), []byte(zebraHealthySample[37:])} {
				_, _ = server.Write(chunk)
			}
			// Real Zebra raw-port connections remain open after ~HS.  Wait for
			// the client to close instead of sending EOF or another response.
			_, _ = server.Read(make([]byte, 1))
		}()
		return client, nil
	}
	started := time.Now()
	state, reasons, category := NewProbe(Config{Dialer: dialer, PhysicalTimeout: 300 * time.Millisecond}).probeZebra(context.Background(), "10.0.0.12:9100")
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("complete response waited for connection close: %s", elapsed)
	}
	if state != PhysicalReady || len(reasons) != 0 || category != nil {
		t.Fatalf("prompt complete probe = %q %#v %v", state, reasons, category)
	}
}

func TestZebraTCPProbeManyEligibleQueuesStaysWithinAggregateBudget(t *testing.T) {
	const queueCount = 16
	results := map[string]commandResult{
		"-r": {stdout: "scheduler is running\n"},
	}
	names := make([]string, 0, queueCount)
	for index := range queueCount {
		name := fmt.Sprintf("zebra-%02d", index)
		names = append(names, name)
		results["-l -p "+name] = commandResult{stdout: "printer " + name + " is idle.\n"}
		results["-a "+name] = commandResult{stdout: name + " accepting requests since Mon\n"}
		results["-W not-completed -o "+name] = commandResult{}
		results["-v "+name] = commandResult{stdout: "device for " + name + ": socket://10.0.0.12:9100\n"}
	}
	transportLines := make([]string, 0, len(names))
	for _, name := range names {
		transportLines = append(transportLines, "device for "+name+": socket://10.0.0.12:9100")
	}
	results["-v"] = commandResult{stdout: strings.Join(transportLines, "\n") + "\n"}
	results["-e"] = commandResult{stdout: strings.Join(names, "\n") + "\n"}
	dialer := func(context.Context, string, string) (net.Conn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			command := make([]byte, 3)
			_, _ = io.ReadFull(server, command)
			for _, chunk := range [][]byte{[]byte(zebraHealthySample[:12]), []byte(zebraHealthySample[12:37]), []byte(zebraHealthySample[37:])} {
				_, _ = server.Write(chunk)
			}
			_, _ = server.Read(make([]byte, 1))
		}()
		return client, nil
	}
	started := time.Now()
	report, err := NewProbe(Config{
		Runner:           &recordingRunner{results: results},
		Dialer:           dialer,
		PhysicalTimeout:  300 * time.Millisecond,
		AggregateTimeout: 100 * time.Millisecond,
		CommandTimeout:   time.Second,
	}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("eligible queue probes exceeded aggregate budget: %s", elapsed)
	}
	if len(report.Queues) != queueCount {
		t.Fatalf("queue count = %d, want %d", len(report.Queues), queueCount)
	}
	for _, queue := range report.Queues {
		if queue.PhysicalState != PhysicalReady || queue.PhysicalErrorCategory != nil {
			t.Fatalf("queue did not receive prompt Zebra evidence: %#v", queue)
		}
	}
}

func TestUSBTransportSnapshotPrioritizesLaterQueueBeforeSlowRichProbe(t *testing.T) {
	const networkName = "network-first"
	const usbName = "usb-late"
	var mu sync.Mutex
	var calls [][]string
	runner := RunnerFunc(func(ctx context.Context, _ string, args []string, _ []string) ([]byte, []byte, error) {
		mu.Lock()
		calls = append(calls, append([]string(nil), args...))
		mu.Unlock()
		key := strings.Join(args, " ")
		switch key {
		case "-r":
			return []byte("scheduler is running\n"), nil, nil
		case "-e":
			return []byte(networkName + "\n" + usbName + "\n"), nil, nil
		case "-v":
			return []byte("device for " + networkName + ": socket://10.0.0.12:9100\ndevice for " + usbName + ": usb://Zebra/model\n"), nil, nil
		case "-l -p " + usbName:
			return []byte("printer " + usbName + " is idle.\n"), nil, nil
		case "-a " + usbName:
			return []byte(usbName + " accepting requests since Mon\n"), nil, nil
		case "-W not-completed -o " + usbName:
			return nil, nil, nil
		case "-l -p " + networkName:
			<-ctx.Done()
			return nil, nil, ctx.Err()
		default:
			return nil, nil, fmt.Errorf("unexpected command %q", key)
		}
	})
	started := time.Now()
	report, err := NewProbe(Config{
		Runner: runner, Clock: fixedClock, Path: "/test/lpstat", CommandTimeout: time.Second,
		AggregateTimeout: 100 * time.Millisecond, MaxStdoutBytes: 4096, MaxStderrBytes: 1024,
	}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("probe exceeded bounded aggregate deadline: %s", elapsed)
	}
	if len(report.Queues) != 2 {
		t.Fatalf("queues = %#v", report.Queues)
	}
	var usb QueueReport
	for _, queue := range report.Queues {
		if queue.Name == usbName {
			usb = queue
		}
	}
	if usb.Name != usbName || usb.DeviceTransport != DeviceTransportUSB {
		t.Fatalf("later USB queue was not retained/classified: %#v", report.Queues)
	}
	if strings.Contains(fmt.Sprintf("%#v", report), "usb://") {
		t.Fatal("raw USB URI leaked into report")
	}

	mu.Lock()
	deferred := append([][]string(nil), calls...)
	mu.Unlock()
	usbStatusIndex, networkStatusIndex := -1, -1
	for index, args := range deferred {
		if strings.Join(args, " ") == "-l -p "+usbName {
			usbStatusIndex = index
		}
		if strings.Join(args, " ") == "-l -p "+networkName {
			networkStatusIndex = index
		}
	}
	if usbStatusIndex < 0 || networkStatusIndex < 0 || usbStatusIndex > networkStatusIndex {
		t.Fatalf("USB queue was not prioritized: calls = %#v", deferred)
	}
}

func TestEnrichedCanonicalFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "printer-report-enriched-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version       int            `json:"version"`
		Type          string         `json:"type"`
		Source        string         `json:"source"`
		ObservedAt    string         `json:"observedAt"`
		Scheduler     SchedulerState `json:"scheduler"`
		Transport     TransportState `json:"transport"`
		ErrorCategory *ErrorCategory `json:"errorCategory"`
		Queues        []QueueReport  `json:"queues"`
		ExpectedHash  string         `json:"expectedHash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	hash, err := CanonicalPayloadHash(Report{
		Version: fixture.Version, Type: fixture.Type, Source: fixture.Source,
		ObservedAt: fixture.ObservedAt, Scheduler: fixture.Scheduler, Transport: fixture.Transport,
		ErrorCategory: fixture.ErrorCategory, Queues: fixture.Queues,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hash != fixture.ExpectedHash {
		t.Fatalf("enriched hash = %s, want %s", hash, fixture.ExpectedHash)
	}
}

func TestPhysicalCanonicalFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "printer-report-physical-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version       int            `json:"version"`
		Type          string         `json:"type"`
		Source        string         `json:"source"`
		ObservedAt    string         `json:"observedAt"`
		Scheduler     SchedulerState `json:"scheduler"`
		Transport     TransportState `json:"transport"`
		ErrorCategory *ErrorCategory `json:"errorCategory"`
		Queues        []QueueReport  `json:"queues"`
		ExpectedHash  string         `json:"expectedHash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	hash, err := CanonicalPayloadHash(Report{
		Version: fixture.Version, Type: fixture.Type, Source: fixture.Source,
		ObservedAt: fixture.ObservedAt, Scheduler: fixture.Scheduler, Transport: fixture.Transport,
		ErrorCategory: fixture.ErrorCategory, Queues: fixture.Queues,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hash != fixture.ExpectedHash {
		t.Fatalf("physical hash = %s, want %s", hash, fixture.ExpectedHash)
	}
	changed := Report{
		Version: fixture.Version, Type: fixture.Type, Source: fixture.Source,
		ObservedAt: fixture.ObservedAt, Scheduler: fixture.Scheduler, Transport: fixture.Transport,
		ErrorCategory: fixture.ErrorCategory, Queues: append([]QueueReport(nil), fixture.Queues...),
	}
	changed.Queues[0].PhysicalState = PhysicalAttention
	changed.Queues[0].PhysicalReasons = []PhysicalReason{PhysicalReasonPaperOut}
	changedHash, err := CanonicalPayloadHash(changed)
	if err != nil || changedHash == hash {
		t.Fatalf("physical state mutation did not change hash: %s/%v", changedHash, err)
	}
	unknownState := Report{
		Version: fixture.Version, Type: fixture.Type, Source: fixture.Source,
		ObservedAt: fixture.ObservedAt, Scheduler: fixture.Scheduler, Transport: fixture.Transport,
		ErrorCategory: fixture.ErrorCategory, Queues: append([]QueueReport(nil), fixture.Queues...),
	}
	unknownState.Queues[0].PhysicalState = PhysicalUnknown
	if err := Validate(unknownState); err == nil {
		t.Fatal("accepted Zebra unknown state without a Zebra error")
	}
	cupsFamily := changed
	cupsFamily.Queues = append([]QueueReport(nil), fixture.Queues...)
	cupsFamily.Queues[1].PhysicalSource = PhysicalSourceCUPS
	cupsFamily.Queues[1].PhysicalReasons = []PhysicalReason{PhysicalReasonPaperOut}
	if err := Validate(cupsFamily); err == nil {
		t.Fatal("accepted Zebra reason under CUPS source")
	}
	zebraFamily := changed
	zebraFamily.Queues = append([]QueueReport(nil), fixture.Queues...)
	zebraFamily.Queues[0].PhysicalState = PhysicalUnknown
	zebraFamily.Queues[0].PhysicalErrorCategory = physicalErrorPtr(PhysicalErrorCUPSInvalid)
	if err := Validate(zebraFamily); err == nil {
		t.Fatal("accepted CUPS error under Zebra source")
	}
}

func TestUnsafeEnumerationNeverReachesRunner(t *testing.T) {
	valid := make([]string, 0, MaxQueues+4)
	for index := range MaxQueues + 4 {
		valid = append(valid, fmt.Sprintf("q%02d", index))
	}
	output := strings.Join(append([]string{"safe", "bad name", "bad;rm", strings.Repeat("x", MaxQueueNameBytes+1), "safe"}, valid...), "\n")
	runner := &recordingRunner{results: map[string]commandResult{
		"-r": {stdout: "scheduler is running\n"},
		"-e": {stdout: output},
	}}
	report, err := testProbe(runner).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(report.Queues) != MaxQueues {
		t.Fatalf("queue count = %d, want %d", len(report.Queues), MaxQueues)
	}
	// Selection must be deterministic before the cap, not only sorted after
	// collection: the leading "safe" queue sorts after all qNN queues.
	for index, queue := range report.Queues {
		if want := fmt.Sprintf("q%02d", index); queue.Name != want {
			t.Fatalf("bounded queue[%d] = %q, want %q", index, queue.Name, want)
		}
	}
	if report.ErrorCategory == nil || *report.ErrorCategory != ErrorEnumerationInvalid {
		t.Fatalf("error category = %v", report.ErrorCategory)
	}
	for _, call := range runner.argv[2:] {
		for _, argument := range call {
			if strings.ContainsAny(argument, "; \t\n\r\x00$()'\"") || len(argument) > MaxQueueNameBytes {
				t.Fatalf("unsafe argument reached runner: %#v", call)
			}
		}
	}
	if len(runner.argv) != 3+MaxQueues*4 {
		t.Fatalf("command count = %d, want %d", len(runner.argv), 3+MaxQueues*4)
	}
}

func TestBoundedOutputTimeoutAndNoRawError(t *testing.T) {
	giant := strings.Repeat("SENSITIVE-STDERR ", 200)
	runner := &recordingRunner{results: map[string]commandResult{
		"-r": {stdout: "scheduler is running\n", stderr: giant},
	}}
	report, err := testProbe(runner).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if report.Transport != TransportUnavailable || report.ErrorCategory == nil || *report.ErrorCategory != ErrorOutputLimit {
		t.Fatalf("bounded report = %#v", report)
	}
	if strings.Contains(fmt.Sprintf("%#v", report), "SENSITIVE-STDERR") {
		t.Fatal("raw stderr leaked into report")
	}

	deadlineRunner := RunnerFunc(func(ctx context.Context, _ string, _ []string, _ []string) ([]byte, []byte, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})
	started := time.Now()
	report, err = NewProbe(Config{Runner: deadlineRunner, Clock: fixedClock, CommandTimeout: 20 * time.Millisecond, AggregateTimeout: time.Second}).Collect(context.Background())
	if err != nil {
		t.Fatalf("timeout Collect: %v", err)
	}
	if time.Since(started) > 500*time.Millisecond || report.Transport != TransportTimeout || report.ErrorCategory == nil || *report.ErrorCategory != ErrorTimeout {
		t.Fatalf("timeout report = %#v", report)
	}
}

func TestCanonicalHashAndValidation(t *testing.T) {
	active := 4
	base := Report{
		Version:    Version,
		Type:       Type,
		Source:     Source,
		ObservedAt: "2026-08-24T12:34:56.123Z",
		Scheduler:  SchedulerRunning,
		Transport:  TransportReachable,
		Queues: []QueueReport{
			{Name: "zebra", QueueState: QueueProcessing, AcceptingJobs: AcceptingNo, ActiveJobs: &active, PhysicalState: PhysicalUnknown, SampledAt: "2026-08-24T12:34:57Z"},
			{Name: "alpha", QueueState: QueueIdle, AcceptingJobs: AcceptingYes, ActiveJobs: nil, PhysicalState: PhysicalUnknown, SampledAt: "2026-08-24T12:34:57Z"},
		},
	}
	if err := Validate(base); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	reordered := base
	reordered.Queues = append([]QueueReport(nil), base.Queues[1], base.Queues[0])
	hashA, err := CanonicalPayloadHash(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}
	hashB, err := CanonicalPayloadHash(reordered)
	if err != nil {
		t.Fatalf("hash reordered: %v", err)
	}
	if hashA != hashB || len(hashA) != 64 {
		t.Fatalf("order changed hash: %q vs %q", hashA, hashB)
	}
	changed := base
	changed.Queues = append([]QueueReport(nil), base.Queues...)
	changed.Queues[0].QueueState = QueueStopped
	hashC, err := CanonicalPayloadHash(changed)
	if err != nil || hashC == hashA {
		t.Fatalf("evidence change did not change hash: %q/%v", hashC, err)
	}
	payload, err := CanonicalPayload(base)
	if err != nil || !strings.HasPrefix(string(payload), "printer-report-canonical-v1\n") || !strings.Contains(string(payload), "queueCount=Mg\n") {
		t.Fatalf("canonical payload = %q, err=%v", payload, err)
	}

	bad := base
	bad.Queues = append([]QueueReport(nil), base.Queues...)
	bad.Queues[0].PhysicalState = "ready"
	if err := Validate(bad); err == nil {
		t.Fatal("accepted inferred physical state")
	}
	bad = base
	bad.ObservedAt = "not-a-time"
	if err := Validate(bad); err == nil {
		t.Fatal("accepted invalid timestamp")
	}
	bad = base
	bad.Queues = append([]QueueReport(nil), base.Queues[0], base.Queues[0])
	if err := Validate(bad); err == nil {
		t.Fatal("accepted duplicate queue")
	}
}

func TestSerializedReportBound(t *testing.T) {
	now := "2026-08-24T12:34:56Z"
	report := Report{Version: Version, Type: Type, Source: Source, ObservedAt: now, Scheduler: SchedulerUnknown, Transport: TransportUnknown, Queues: make([]QueueReport, MaxQueues)}
	for index := range report.Queues {
		report.Queues[index] = QueueReport{Name: fmt.Sprintf("queue-%d", index), QueueState: QueueUnknown, AcceptingJobs: AcceptingUnknown, PhysicalState: PhysicalUnknown, SampledAt: now}
	}
	encoded, err := Marshal(report)
	size := len(encoded)
	if err != nil || size >= MaxReportBytes {
		t.Fatalf("size=%d err=%v", size, err)
	}
	for index := range report.Queues {
		report.Queues[index].Name = fmt.Sprintf("%03d%s", index, strings.Repeat("q", MaxQueueNameBytes-3))
	}
	if _, err := Marshal(report); err != nil {
		t.Fatalf("max-safe report rejected: %v", err)
	}

	bad := report
	bad.Queues = append([]QueueReport(nil), report.Queues...)
	bad.Queues = append(bad.Queues, QueueReport{Name: "overflow", QueueState: QueueUnknown, AcceptingJobs: AcceptingUnknown, PhysicalState: PhysicalUnknown, SampledAt: now})
	if err := Validate(bad); err == nil {
		t.Fatal("accepted >32 queues")
	}
}

func TestPrinterCanonicalHashFixture(t *testing.T) {
	active := 2
	report := Report{Version: Version, Type: Type, Source: Source, ObservedAt: "2026-08-24T12:34:56.123456789Z", Scheduler: SchedulerRunning, Transport: TransportReachable, Queues: []QueueReport{
		{Name: "a_1", QueueState: QueueIdle, AcceptingJobs: AcceptingYes, PhysicalState: PhysicalUnknown, SampledAt: "2026-08-24T12:34:56.123456789Z"},
		{Name: "aa", QueueState: QueueProcessing, AcceptingJobs: AcceptingNo, ActiveJobs: &active, PhysicalState: PhysicalUnknown, SampledAt: "2026-08-24T12:34:56Z"},
		{Name: "a.1", QueueState: QueueStopped, AcceptingJobs: AcceptingUnknown, PhysicalState: PhysicalUnknown, SampledAt: "2026-08-24T12:34:56Z"},
		{Name: "a-1", QueueState: QueueUnknown, AcceptingJobs: AcceptingYes, PhysicalState: PhysicalUnknown, SampledAt: "2026-08-24T12:34:56Z"},
	}}
	hash, err := CanonicalPayloadHash(report)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "257d96ee73ca98631bc29021c4f4f41b93b3fc91c2e76d230670771ed288ef11"
	if hash != expected {
		t.Fatalf("hash=%s expected=%s", hash, expected)
	}
}

func TestParseAcceptingJobsWithCUPSReasonContinuation(t *testing.T) {
	for _, test := range []struct {
		name, output string
		want         AcceptingState
	}{
		{"reason", "q not accepting requests since Thu Aug 27 12:00:00 2026 -\n\treason unknown\n", AcceptingNo},
		{"multiline-crlf", "Q not accepting requests since Thu -\r\n\tprivate reason\r\n\tmore detail\r\n", AcceptingNo},
		{"other-record", "q not accepting requests since Thu -\n\treason\nother accepting requests since Thu\n", AcceptingUnknown},
		{"other-header", "other not accepting requests since Thu -\n\treason\n", AcceptingUnknown},
		{"malformed-header", "q not accepting requestsINVALID since Thu -\n\treason\n", AcceptingUnknown},
		{"missing-time", "q not accepting requests since \n\treason\n", AcceptingUnknown},
		{"indented-header", "\tq not accepting requests since Thu -\n\treason\n", AcceptingUnknown},
		{"unindented-reason", "q not accepting requests since Thu -\nreason\n", AcceptingUnknown},
		{"empty-reason", "q not accepting requests since Thu -\n\t\n", AcceptingUnknown},
		{"nul", "q not accepting requests since Thu -\n\treason\x00\n", AcceptingUnknown},
		{"oversized", "q not accepting requests since Thu -\n\t" + strings.Repeat("x", defaultStdoutBytes), AcceptingUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ParseAcceptingJobs("q", []byte(test.output)); got != test.want {
				t.Fatalf("state=%s want=%s", got, test.want)
			}
		})
	}
}

func TestProbePreservesNotAcceptingWithPrivateReason(t *testing.T) {
	const reason = "private operator reason"
	runner := RunnerFunc(func(_ context.Context, _ string, args, _ []string) ([]byte, []byte, error) {
		output := ""
		switch strings.Join(args, " ") {
		case "-r":
			output = "scheduler is running\n"
		case "-e":
			output = "queue\n"
		case "-v":
			output = "device for queue: usb://Other/Printer\n"
		case "-l -p queue":
			output = "printer queue is idle. enabled since Thu\n"
		case "-a queue":
			output = "queue not accepting requests since Thu Aug 27 12:00:00 2026 -\n\t" + reason + "\n"
		}
		return []byte(output), nil, nil
	})
	report, err := testProbe(runner).Collect(context.Background())
	if err != nil || len(report.Queues) != 1 {
		t.Fatalf("Collect=%+v error=%v", report, err)
	}
	queue := report.Queues[0]
	if queue.AcceptingJobs != AcceptingNo || queue.ErrorCategory != nil {
		t.Fatalf("valid CUPS rejecting state lost: %+v", queue)
	}
	encoded, err := json.Marshal(report)
	if err != nil || bytes.Contains(encoded, []byte(reason)) {
		t.Fatal("private reason entered report")
	}
}

func TestExecEnforcesOutputLimits(t *testing.T) {
	for _, script := range []string{"printf 123456789", "printf 123456789 >&2"} {
		stdout, stderr, err := runExec(t.Context(), "/bin/sh", []string{"-c", script}, 4, 4)
		if !errors.Is(err, errOutputLimit) || len(stdout) > 4 || len(stderr) > 4 {
			t.Fatalf("output bound bypassed: stdout=%q stderr=%q error=%v", stdout, stderr, err)
		}
	}
}
