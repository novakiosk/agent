// Package printer contains the deliberately small, read-only local printer
// evidence probe. It combines fixed CUPS queries with bounded Zebra host
// status probes and keeps queue state separate from physical evidence.
package printer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// Version and Type identify the JSON evidence shape.  Source identifies
	// the local implementation and is intentionally separate from Type so a
	// later bridge can use the same report shape with a different source.
	Version = 1
	Type    = "printer.report"
	Source  = "local-cups-lpstat-v1"

	// MaxQueues is an intentional upper bound on enumeration.  The probe
	// never issues a command for a queue beyond this limit.
	MaxQueues = 32
	// MaxQueueNameBytes is the CUPS destination name bound accepted by the
	// parser.  Names are ASCII and contain no shell metacharacters.
	MaxQueueNameBytes = 127
	// MaxReportBytes is a hard JSON payload bound used by Validate and
	// Marshal.  Normal reports are substantially smaller than this limit.
	MaxReportBytes = 16 * 1024
	// MaxPPDBytes bounds generated PPD inspection while accommodating the
	// installed CUPS Zebra sample driver output.
	MaxPPDBytes = 512 * 1024

	defaultCommandTimeout   = 2 * time.Second
	defaultAggregateTimeout = 8 * time.Second
	defaultStdoutBytes      = 8 * 1024
	defaultStderrBytes      = 4 * 1024
	defaultPath             = "/usr/bin/lpstat"
	defaultPhysicalTimeout  = 500 * time.Millisecond
	maxZebraResponseBytes   = 4 * 1024
	MaxQueueOptions         = 32
	MaxOptionChoices        = 128
)

// SchedulerState is the state explicitly reported by lpstat -r.
type SchedulerState string

const (
	SchedulerRunning SchedulerState = "running"
	SchedulerStopped SchedulerState = "stopped"
	SchedulerUnknown SchedulerState = "unknown"
)

// TransportState describes the ability to obtain a local lpstat sample.  It
// does not describe a printer's physical state.
type TransportState string

const (
	TransportReachable   TransportState = "reachable"
	TransportUnavailable TransportState = "unavailable"
	TransportTimeout     TransportState = "timeout"
	TransportUnknown     TransportState = "unknown"
)

// QueueState is the queue/printer state visible through CUPS.
type QueueState string

const (
	QueueIdle       QueueState = "idle"
	QueueProcessing QueueState = "processing"
	QueueStopped    QueueState = "stopped"
	QueueUnknown    QueueState = "unknown"
)

// AcceptingState is whether CUPS says that a queue accepts jobs.
type AcceptingState string

const (
	AcceptingYes     AcceptingState = "yes"
	AcceptingNo      AcceptingState = "no"
	AcceptingUnknown AcceptingState = "unknown"
)

// PhysicalState is a bounded best-effort physical evidence signal.  Unknown
// remains the honest result when the queue has no supported physical probe or
// the printer does not answer one.
type PhysicalState string

const (
	PhysicalUnknown   PhysicalState = "unknown"
	PhysicalReady     PhysicalState = "ready"
	PhysicalAttention PhysicalState = "attention"
)

type PhysicalSource string

const (
	PhysicalSourceZebraTCP PhysicalSource = "zebra_host_status_tcp_v1"
	PhysicalSourceZebraUSB PhysicalSource = "zebra_host_status_usb_v1"
	PhysicalSourceCUPS     PhysicalSource = "cups_state_reasons_v1"
)

type PhysicalReason string

const (
	PhysicalReasonPaperOut          PhysicalReason = "paper_out"
	PhysicalReasonPaused            PhysicalReason = "paused"
	PhysicalReasonBufferFull        PhysicalReason = "buffer_full"
	PhysicalReasonDiagnosticMode    PhysicalReason = "diagnostic_mode"
	PhysicalReasonPartialFormat     PhysicalReason = "partial_format"
	PhysicalReasonConfigurationLost PhysicalReason = "configuration_data_lost"
	PhysicalReasonUnderTemperature  PhysicalReason = "under_temperature"
	PhysicalReasonOverTemperature   PhysicalReason = "over_temperature"
	PhysicalReasonHeadUp            PhysicalReason = "head_up"
	PhysicalReasonRibbonOut         PhysicalReason = "ribbon_out"
	PhysicalReasonMediaEmpty        PhysicalReason = "media_empty"
	PhysicalReasonMediaLow          PhysicalReason = "media_low"
	PhysicalReasonMediaJam          PhysicalReason = "media_jam"
	PhysicalReasonCoverOpen         PhysicalReason = "cover_open"
	PhysicalReasonOffline           PhysicalReason = "offline"
	PhysicalReasonMarkerSupplyEmpty PhysicalReason = "marker_supply_empty"
	PhysicalReasonMarkerSupplyLow   PhysicalReason = "marker_supply_low"
)

type PhysicalErrorCategory string

const (
	PhysicalErrorZebraConnect        PhysicalErrorCategory = "zebra_connect_failed"
	PhysicalErrorZebraWrite          PhysicalErrorCategory = "zebra_write_failed"
	PhysicalErrorZebraTimeout        PhysicalErrorCategory = "zebra_timeout"
	PhysicalErrorZebraNoResponse     PhysicalErrorCategory = "zebra_no_response"
	PhysicalErrorZebraMalformed      PhysicalErrorCategory = "zebra_malformed"
	PhysicalErrorZebraOversize       PhysicalErrorCategory = "zebra_oversize"
	PhysicalErrorZebraUSBUnavailable PhysicalErrorCategory = "zebra_usb_device_unavailable"
	PhysicalErrorZebraUSBPermission  PhysicalErrorCategory = "zebra_usb_permission_denied"
	PhysicalErrorZebraUSBBusy        PhysicalErrorCategory = "zebra_usb_interface_busy"
	PhysicalErrorCUPSUnavailable     PhysicalErrorCategory = "cups_state_reasons_unavailable"
	PhysicalErrorCUPSInvalid         PhysicalErrorCategory = "cups_state_reasons_invalid"
)

// ErrorCategory is a redacted, stable diagnostic category.  Raw lpstat
// output, stderr, command paths, and process errors are never placed in a
// Report.
type ErrorCategory string

const (
	ErrorBinaryMissing      ErrorCategory = "binary_missing"
	ErrorTimeout            ErrorCategory = "timeout"
	ErrorContextCanceled    ErrorCategory = "context_canceled"
	ErrorOutputLimit        ErrorCategory = "output_limit"
	ErrorCommandFailed      ErrorCategory = "command_failed"
	ErrorEnumerationInvalid ErrorCategory = "enumeration_invalid"
	ErrorEnumerationLimit   ErrorCategory = "enumeration_limit"
	ErrorQueueStatusFailed  ErrorCategory = "queue_status_failed"
	ErrorQueueOutputInvalid ErrorCategory = "queue_output_invalid"
)

type DeviceTransport string

const (
	DeviceTransportUSB     DeviceTransport = "usb"
	DeviceTransportNetwork DeviceTransport = "network"
	DeviceTransportUnknown DeviceTransport = "unknown"
)

// Report is a bounded, JSON-friendly snapshot of local CUPS evidence.
// ErrorCategory is nullable because a fully successful probe has no error.
// Queues are normalized and sorted by the probe, although validation accepts
// any input order and canonicalization sorts a copy.
type Report struct {
	USBDiscovery  *USBDiscovery  `json:"usbDiscovery,omitempty"`
	Version       int            `json:"version"`
	Type          string         `json:"type"`
	Source        string         `json:"source"`
	ObservedAt    string         `json:"observedAt"`
	Scheduler     SchedulerState `json:"scheduler"`
	Transport     TransportState `json:"transport"`
	ErrorCategory *ErrorCategory `json:"errorCategory"`
	Queues        []QueueReport  `json:"queues"`
}

// QueueReport contains independent CUPS axes.  ActiveJobs is null when the
// command did not produce an unambiguous successful count.  Physical evidence
// is optional and never contains a URI, host, raw response, or stderr.
type QueueReport struct {
	Name                  string                 `json:"name"`
	QueueState            QueueState             `json:"queueState"`
	AcceptingJobs         AcceptingState         `json:"acceptingJobs"`
	ActiveJobs            *int                   `json:"activeJobs"`
	PhysicalState         PhysicalState          `json:"physicalState"`
	SampledAt             string                 `json:"sampledAt"`
	ErrorCategory         *ErrorCategory         `json:"errorCategory,omitempty"`
	DeviceTransport       DeviceTransport        `json:"deviceTransport,omitempty"`
	PhysicalSource        PhysicalSource         `json:"physicalSource,omitempty"`
	PhysicalReasons       []PhysicalReason       `json:"physicalReasons,omitempty"`
	PhysicalErrorCategory *PhysicalErrorCategory `json:"physicalErrorCategory,omitempty"`
	Options               []QueueOption          `json:"options,omitempty"`
	CustomMedia           *CustomMediaBounds     `json:"customMedia,omitempty"`
}

type CustomMediaBounds struct {
	MinWidthMM      float64  `json:"minWidthMm"`
	MaxWidthMM      float64  `json:"maxWidthMm"`
	MinHeightMM     float64  `json:"minHeightMm"`
	MaxHeightMM     float64  `json:"maxHeightMm"`
	Unit            string   `json:"unit"`
	DefaultWidthMM  *float64 `json:"defaultWidthMm,omitempty"`
	DefaultHeightMM *float64 `json:"defaultHeightMm,omitempty"`
}

// QueueOption contains only bounded names and values advertised by CUPS.
// Human labels, PPD paths, device URIs, and arbitrary backend data are not
// carried across the control-plane boundary.
type QueueOption struct {
	Name    string   `json:"name"`
	Default *string  `json:"default"`
	Choices []string `json:"choices"`
}

// VariablePaperBounds is the bounded, redacted capability needed for safe
// custom media. It contains numeric points only; PPD paths and raw text never
// leave the helper/report boundary.
type VariablePaperBounds struct {
	MinWidthPoints  float64
	MinHeightPoints float64
	MaxWidthPoints  float64
	MaxHeightPoints float64
}

var (
	variablePaperBoundsPattern  = regexp.MustCompile(`(?m)^\*ParamCustomPageSize\s+(Width|Height):\s+(?:[12]) points ([0-9]+(?:\.[0-9]+)?) ([0-9]+(?:\.[0-9]+)?)\s*$`)
	variablePaperDefaultPattern = regexp.MustCompile(`(?m)^\*DefaultPageSize:\s+Custom\.([0-9]+(?:\.[0-9]+)?)x([0-9]+(?:\.[0-9]+)?)mm\s*$`)
)

// ParseVariablePaperBounds accepts the generated Zebra PPD capability lines
// and rejects ambiguous or unbounded input.
func ParseVariablePaperBounds(data []byte) (VariablePaperBounds, bool) {
	if len(data) == 0 || len(data) > MaxPPDBytes {
		return VariablePaperBounds{}, false
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !strings.Contains(text, "*CustomPageSize True") {
		return VariablePaperBounds{}, false
	}
	var bounds VariablePaperBounds
	seenW, seenH := false, false
	for _, match := range variablePaperBoundsPattern.FindAllStringSubmatch(text, -1) {
		min, e1 := strconv.ParseFloat(match[2], 64)
		max, e2 := strconv.ParseFloat(match[3], 64)
		if e1 != nil || e2 != nil || min < 0 || max <= min || max > 100000 {
			return VariablePaperBounds{}, false
		}
		if match[1] == "Width" {
			if seenW {
				return VariablePaperBounds{}, false
			}
			bounds.MinWidthPoints, bounds.MaxWidthPoints, seenW = min, max, true
		} else {
			if seenH {
				return VariablePaperBounds{}, false
			}
			bounds.MinHeightPoints, bounds.MaxHeightPoints, seenH = min, max, true
		}
	}
	return bounds, seenW && seenH
}

func parseVariablePaperDefault(data []byte, bounds VariablePaperBounds) (float64, float64, bool) {
	matches := variablePaperDefaultPattern.FindAllSubmatch(data, -1)
	if len(matches) != 1 {
		return 0, 0, false
	}
	width, widthErr := strconv.ParseFloat(string(matches[0][1]), 64)
	height, heightErr := strconv.ParseFloat(string(matches[0][2]), 64)
	widthPoints, heightPoints := width*72/25.4, height*72/25.4
	if widthErr != nil || heightErr != nil || widthPoints < bounds.MinWidthPoints-0.01 || widthPoints > bounds.MaxWidthPoints+0.01 || heightPoints < bounds.MinHeightPoints-0.01 || heightPoints > bounds.MaxHeightPoints+0.01 || !hundredthMM(width) || !hundredthMM(height) {
		return 0, 0, false
	}
	return width, height, true
}

func hundredthMM(value float64) bool {
	return finiteNumber(value) && math.Abs(value*100-math.Round(value*100)) < 0.000001
}

// Runner is the only process-execution seam.  Production uses an
// exec.CommandContext-backed implementation; tests may inject a runner and
// inspect the exact path, argv, environment, and context deadline.
type Runner interface {
	Run(ctx context.Context, path string, args []string, env []string) (stdout, stderr []byte, err error)
}

// RunnerFunc adapts a function to Runner.
type RunnerFunc func(context.Context, string, []string, []string) ([]byte, []byte, error)

// Dialer is injectable so Zebra status handling can be tested without
// opening an uncontrolled network connection.
type Dialer func(context.Context, string, string) (net.Conn, error)

// USBHostStatusProber reads one Zebra host-status response for the exact
// serial selected by a validated CUPS USB URI. An empty category means the
// returned payload is complete transport evidence ready for strict parsing.
type USBHostStatusProber interface {
	ProbeZebraHostStatus(context.Context, string, time.Duration) ([]byte, PhysicalErrorCategory)
}

func (f RunnerFunc) Run(ctx context.Context, path string, args []string, env []string) ([]byte, []byte, error) {
	return f(ctx, path, args, env)
}

// Config controls Probe.  Zero values select production-safe defaults.  Path
// is injectable solely for deterministic tests; normal operation always uses
// /usr/bin/lpstat.
type Config struct {
	USBSysfsRoot     string
	Runner           Runner
	Clock            func() time.Time
	Path             string
	OptionsPath      string
	CommandTimeout   time.Duration
	AggregateTimeout time.Duration
	MaxStdoutBytes   int
	MaxStderrBytes   int
	PhysicalTimeout  time.Duration
	Dialer           Dialer
	USBProber        USBHostStatusProber
	PPDDir           string
}

// Probe runs the fixed lpstat evidence collection sequence.
type Probe struct {
	USBSysfsRoot string
	// The exported fields are convenient for small integrations and tests.
	// NewProbe remains the preferred constructor because it fills production
	// defaults.  A zero field uses the same default as NewProbe.
	Runner           Runner
	Clock            func() time.Time
	Path             string
	OptionsPath      string
	CommandTimeout   time.Duration
	AggregateTimeout time.Duration
	MaxStdoutBytes   int
	MaxStderrBytes   int
	PhysicalTimeout  time.Duration
	Dialer           Dialer
	USBProber        USBHostStatusProber
	PPDDir           string
}

// NewProbe creates a probe.  A variadic Config keeps the zero-argument form
// convenient while allowing deterministic tests to pass one Config.
func NewProbe(config ...Config) *Probe {
	c := Config{}
	if len(config) > 0 {
		c = config[0]
	}
	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}
	path := c.Path
	if path == "" {
		path = defaultPath
	}
	commandTimeout := c.CommandTimeout
	if commandTimeout <= 0 {
		commandTimeout = defaultCommandTimeout
	}
	aggregateTimeout := c.AggregateTimeout
	if aggregateTimeout <= 0 {
		aggregateTimeout = defaultAggregateTimeout
	}
	maxStdout := c.MaxStdoutBytes
	if maxStdout <= 0 {
		maxStdout = defaultStdoutBytes
	}
	maxStderr := c.MaxStderrBytes
	if maxStderr <= 0 {
		maxStderr = defaultStderrBytes
	}
	physicalTimeout := c.PhysicalTimeout
	if physicalTimeout <= 0 {
		physicalTimeout = defaultPhysicalTimeout
	}
	usbProber := c.USBProber
	if usbProber == nil {
		usbProber = newUSBHostStatusProber()
	}
	ppdDir := c.PPDDir
	if ppdDir == "" {
		ppdDir = "/etc/cups/ppd"
	}
	return &Probe{
		USBSysfsRoot:     c.USBSysfsRoot,
		Runner:           c.Runner,
		Clock:            clock,
		Path:             path,
		OptionsPath:      c.OptionsPath,
		CommandTimeout:   commandTimeout,
		AggregateTimeout: aggregateTimeout,
		MaxStdoutBytes:   maxStdout,
		MaxStderrBytes:   maxStderr,
		PhysicalTimeout:  physicalTimeout,
		Dialer:           c.Dialer,
		USBProber:        usbProber,
		PPDDir:           ppdDir,
	}
}

// Collect executes the exact read-only probe.  Expected command failures are
// represented in the returned report and do not cause a raw process error to
// escape.  Invalid Probe configuration or a nil context returns an error.
func (p *Probe) Collect(ctx context.Context) (result Report, resultErr error) {
	defer func() {
		if p != nil && ctx != nil && p.USBSysfsRoot != "" && resultErr == nil {
			result.USBDiscovery = p.discoverUSB(ctx)
			result, resultErr = fitCollectedReport(result)
		}
	}()
	if p == nil {
		return Report{}, errors.New("printer: nil probe")
	}
	if ctx == nil {
		return Report{}, errors.New("printer: nil context")
	}
	commandTimeout, aggregateTimeout, maxStdoutBytes, maxStderrBytes, path := p.commandSettings()
	if commandTimeout <= 0 || aggregateTimeout <= 0 || maxStdoutBytes <= 0 || maxStderrBytes <= 0 || path == "" {
		return Report{}, errors.New("printer: invalid probe configuration")
	}

	clock := p.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock()
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	report := Report{
		Version:    Version,
		Type:       Type,
		Source:     Source,
		ObservedAt: now.Format(time.RFC3339Nano),
		Scheduler:  SchedulerUnknown,
		Transport:  TransportUnknown,
		Queues:     make([]QueueReport, 0),
	}

	aggregateCtx, cancel := context.WithTimeout(ctx, aggregateTimeout)
	defer cancel()

	stdout, _, err, category := p.command(aggregateCtx, []string{"-r"})
	if err != nil {
		// Some CUPS builds return a nonzero status while still emitting the
		// explicit stopped sentence.  That sentence is sufficient scheduler
		// evidence, but only when the command itself was not a timeout or
		// missing-binary failure.
		if category == ErrorCommandFailed && ParseSchedulerOutput(stdout) == SchedulerStopped {
			report.Scheduler = SchedulerStopped
			report.Transport = TransportReachable
			stdout, _, err, category = p.command(aggregateCtx, []string{"-e"})
			if err != nil {
				report.ErrorCategory = categoryPtr(category)
				report.Transport = transportForCategory(category)
				return report, nil
			}
			queues, enumCategory := parseQueueEnumeration(stdout)
			if enumCategory != "" {
				report.ErrorCategory = categoryPtr(enumCategory)
			}
			return p.collectQueues(aggregateCtx, report, queues, clock)
		}
		report.ErrorCategory = categoryPtr(category)
		report.Transport = transportForCategory(category)
		if category == ErrorContextCanceled && ctx.Err() == nil {
			report.ErrorCategory = categoryPtr(ErrorTimeout)
			report.Transport = TransportTimeout
		}
		return report, nil
	}
	report.Scheduler = ParseSchedulerOutput(stdout)
	report.Transport = TransportReachable

	enumeration, _, err, category := p.command(aggregateCtx, []string{"-e"})
	if err != nil {
		report.ErrorCategory = categoryPtr(category)
		report.Transport = transportForCategory(category)
		if report.Scheduler != SchedulerUnknown && (category == ErrorQueueStatusFailed || category == ErrorEnumerationInvalid) {
			report.Transport = TransportReachable
		}
		return report, nil
	}

	queues, enumCategory := parseQueueEnumeration(enumeration)
	if enumCategory != "" {
		report.ErrorCategory = categoryPtr(enumCategory)
	}
	return p.collectQueues(aggregateCtx, report, queues, clock)
}

// transportEvidence is intentionally process-local. The raw lpstat device
// line is needed by the physical Zebra probes, but never crosses the report
// boundary or gets retained after this collection.
type transportEvidence struct {
	transport DeviceTransport
	line      []byte
}

type transportPass struct {
	evidence map[string]transportEvidence
	errors   map[string]ErrorCategory
}

// collectTransportEvidence performs the cheap transport pass before any
// queue's richer probes. lpstat can return all device lines in one bounded
// invocation; only queues from the already validated enumeration are mapped.
// A partial snapshot falls back to exact per-queue -v calls for names that do
// not have a trustworthy line, still before status/jobs/options/physical work.
func (p *Probe) collectTransportEvidence(aggregateCtx context.Context, queues []string) transportPass {
	pass := transportPass{
		evidence: make(map[string]transportEvidence, len(queues)),
		errors:   make(map[string]ErrorCategory),
	}
	if len(queues) == 0 {
		return pass
	}

	snapshot, _, snapshotErr, _ := p.command(aggregateCtx, []string{"-v"})
	if snapshotErr == nil {
		pass.evidence, _ = parseDeviceTransportSnapshot(snapshot, queues)
	}

	// Missing entries are the only ones that need a fallback. Valid entries
	// from an otherwise incomplete snapshot remain useful and independently
	// redacted, while malformed/duplicate entries are excluded by the parser.
	for _, name := range queues {
		if _, ok := pass.evidence[name]; ok {
			continue
		}
		output, _, err, category := p.command(aggregateCtx, []string{"-v", name})
		if err != nil {
			pass.errors[name] = category
			continue
		}
		transport := ParseDeviceTransport(name, output)
		if transport == DeviceTransportUnknown && !isWellFormedDeviceTransportLine(name, output) {
			pass.errors[name] = ErrorQueueOutputInvalid
			continue
		}
		pass.evidence[name] = transportEvidence{transport: transport, line: append([]byte(nil), output...)}
	}
	return pass
}

func (p *Probe) collectQueues(aggregateCtx context.Context, report Report, queues []string, clock func() time.Time) (Report, error) {
	transportPass := p.collectTransportEvidence(aggregateCtx, queues)
	orderedQueues := prioritizeUSBQueues(queues, transportPass.evidence)
	for _, name := range orderedQueues {
		sampled := clock()
		if sampled.IsZero() {
			sampled = time.Now()
		}
		sampled = sampled.UTC()
		queue := QueueReport{
			Name:            name,
			QueueState:      QueueUnknown,
			AcceptingJobs:   AcceptingUnknown,
			PhysicalState:   PhysicalUnknown,
			SampledAt:       sampled.Format(time.RFC3339Nano),
			DeviceTransport: DeviceTransportUnknown,
		}
		transportOutput := []byte(nil)
		var transportErr error
		if evidence, ok := transportPass.evidence[name]; ok {
			queue.DeviceTransport = evidence.transport
			transportOutput = evidence.line
			if queue.DeviceTransport == DeviceTransportUnknown {
				setQueueError(&queue, ErrorQueueOutputInvalid)
			}
		} else if category, ok := transportPass.errors[name]; ok {
			setQueueError(&queue, category)
			transportErr = errors.New("printer: transport evidence unavailable")
		}

		status, _, statusErr, statusCategory := p.command(aggregateCtx, []string{"-l", "-p", name})
		if statusErr == nil {
			queue.QueueState = ParseQueueState(name, status)
			if queue.QueueState == QueueUnknown {
				setQueueError(&queue, ErrorQueueOutputInvalid)
			}
		} else {
			setQueueError(&queue, statusCategory)
		}

		accepting, _, acceptingErr, acceptingCategory := p.command(aggregateCtx, []string{"-a", name})
		if acceptingErr == nil {
			queue.AcceptingJobs = ParseAcceptingJobs(name, accepting)
			if queue.AcceptingJobs == AcceptingUnknown {
				setQueueError(&queue, ErrorQueueOutputInvalid)
			}
		} else {
			setQueueError(&queue, acceptingCategory)
		}

		jobs, _, jobsErr, jobsCategory := p.command(aggregateCtx, []string{"-W", "not-completed", "-o", name})
		if jobsErr == nil {
			queue.ActiveJobs = ParseActiveJobs(name, jobs)
			// Nil means a successful but ambiguous output. Empty successful
			// output is explicitly and correctly represented as a pointer to 0.
			if queue.ActiveJobs == nil && len(bytes.TrimSpace(jobs)) != 0 {
				setQueueError(&queue, ErrorQueueOutputInvalid)
			}
		} else {
			setQueueError(&queue, jobsCategory)
		}
		if p.OptionsPath != "" {
			options, _, optionsErr, _ := p.commandAt(aggregateCtx, p.OptionsPath, []string{"-p", name, "-l"})
			if optionsErr == nil {
				queue.Options = ParseQueueOptions(options)
			}
		}
		if bounds, ok := readQueuePPDBounds(p.ppdDirValue(), name); ok {
			queue.CustomMedia = &bounds
		}

		p.collectPhysicalEvidence(aggregateCtx, &queue, name, status, statusErr, transportOutput, transportErr)
		report.Queues = append(report.Queues, queue)
	}
	return fitCollectedReport(report)
}

var errReportSize = errors.New("printer: report size limit")

// fitCollectedReport trims optional records before dropping queues. Collection
// order puts USB queues first, so trimming from the end preserves that priority.
func fitCollectedReport(report Report) (Report, error) {
	for {
		_, err := CanonicalPayload(report)
		if err == nil {
			sort.Slice(report.Queues, func(i, j int) bool { return report.Queues[i].Name < report.Queues[j].Name })
			return report, nil
		}
		if !errors.Is(err, errReportSize) {
			return Report{}, err
		}
		trimmed := false
		for i := len(report.Queues) - 1; i >= 0; i-- {
			queue := &report.Queues[i]
			if len(queue.Options) > 0 {
				queue.Options = queue.Options[:len(queue.Options)-1]
				setQueueError(queue, ErrorOutputLimit)
				trimmed = true
				break
			}
		}
		if trimmed {
			continue
		}
		if len(report.Queues) == 0 {
			return Report{}, err
		}
		report.Queues = report.Queues[:len(report.Queues)-1]
		if report.ErrorCategory == nil {
			report.ErrorCategory = categoryPtr(ErrorEnumerationLimit)
		}
	}
}

func prioritizeUSBQueues(queues []string, evidence map[string]transportEvidence) []string {
	ordered := make([]string, 0, len(queues))
	for _, name := range queues {
		if item, ok := evidence[name]; ok && item.transport == DeviceTransportUSB {
			ordered = append(ordered, name)
		}
	}
	for _, name := range queues {
		if item, ok := evidence[name]; !ok || item.transport != DeviceTransportUSB {
			ordered = append(ordered, name)
		}
	}
	return ordered
}

func (p *Probe) ppdDirValue() string {
	if p.PPDDir != "" {
		return p.PPDDir
	}
	return "/etc/cups/ppd"
}

func readQueuePPDBounds(directory, queueName string) (CustomMediaBounds, bool) {
	if !isSafeQueueName(queueName) || filepath.Base(queueName) != queueName || strings.Contains(directory, "..") {
		return CustomMediaBounds{}, false
	}
	path := filepath.Join(directory, queueName+".ppd")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxPPDBytes || info.Mode().Perm()&0o022 != 0 {
		return CustomMediaBounds{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return CustomMediaBounds{}, false
	}
	bounds, ok := ParseVariablePaperBounds(data)
	if !ok {
		return CustomMediaBounds{}, false
	}
	media := CustomMediaBounds{MinWidthMM: bounds.MinWidthPoints * 25.4 / 72, MaxWidthMM: bounds.MaxWidthPoints * 25.4 / 72, MinHeightMM: bounds.MinHeightPoints * 25.4 / 72, MaxHeightMM: bounds.MaxHeightPoints * 25.4 / 72, Unit: "mm"}
	if width, height, ok := parseVariablePaperDefault(data, bounds); ok {
		media.DefaultWidthMM = &width
		media.DefaultHeightMM = &height
	}
	return media, validCustomMediaBounds(media)
}

func (p *Probe) collectPhysicalEvidence(ctx context.Context, queue *QueueReport, name string, status []byte, statusErr error, transport []byte, transportErr error) {
	if queue == nil {
		return
	}
	if transportErr == nil {
		if target, ok := parseZebraTarget(name, transport); ok {
			state, reasons, category := p.probeZebra(ctx, target)
			queue.PhysicalState = state
			queue.PhysicalSource = PhysicalSourceZebraTCP
			queue.PhysicalReasons = reasons
			queue.PhysicalErrorCategory = category
			return
		}
		if queue.ActiveJobs != nil && *queue.ActiveJobs == 0 {
			if serial, ok := parseZebraUSBSerial(name, transport); ok {
				if prober := p.usbHostStatusProber(); prober != nil {
					state, reasons, category := p.probeZebraUSB(ctx, prober, serial)
					queue.PhysicalState = state
					queue.PhysicalSource = PhysicalSourceZebraUSB
					queue.PhysicalReasons = reasons
					queue.PhysicalErrorCategory = category
					return
				}
			}
		}
	}
	queue.PhysicalSource = PhysicalSourceCUPS
	if statusErr != nil {
		queue.PhysicalErrorCategory = physicalErrorPtr(PhysicalErrorCUPSUnavailable)
		return
	}
	reasons, valid := ParseCUPSStateReasons(status)
	if !valid {
		queue.PhysicalErrorCategory = physicalErrorPtr(PhysicalErrorCUPSInvalid)
		return
	}
	queue.PhysicalReasons = reasons
	if len(reasons) > 0 {
		queue.PhysicalState = PhysicalAttention
	}
}

func setQueueError(queue *QueueReport, category ErrorCategory) {
	if queue != nil && queue.ErrorCategory == nil && category != "" {
		queue.ErrorCategory = categoryPtr(category)
	}
}

func (p *Probe) commandSettings() (commandTimeout, aggregateTimeout time.Duration, maxStdoutBytes, maxStderrBytes int, path string) {
	commandTimeout = p.CommandTimeout
	if commandTimeout == 0 {
		commandTimeout = defaultCommandTimeout
	}
	aggregateTimeout = p.AggregateTimeout
	if aggregateTimeout == 0 {
		aggregateTimeout = defaultAggregateTimeout
	}
	maxStdoutBytes = p.MaxStdoutBytes
	if maxStdoutBytes == 0 {
		maxStdoutBytes = defaultStdoutBytes
	}
	maxStderrBytes = p.MaxStderrBytes
	if maxStderrBytes == 0 {
		maxStderrBytes = defaultStderrBytes
	}
	path = p.Path
	if path == "" {
		path = defaultPath
	}
	return commandTimeout, aggregateTimeout, maxStdoutBytes, maxStderrBytes, path
}

func (p *Probe) command(aggregate context.Context, args []string) ([]byte, []byte, error, ErrorCategory) {
	commandTimeout, _, maxStdoutBytes, maxStderrBytes, path := p.commandSettings()
	return p.commandAtWithLimits(aggregate, path, args, commandTimeout, maxStdoutBytes, maxStderrBytes)
}

func (p *Probe) commandAt(aggregate context.Context, path string, args []string) ([]byte, []byte, error, ErrorCategory) {
	commandTimeout, _, maxStdoutBytes, maxStderrBytes, _ := p.commandSettings()
	return p.commandAtWithLimits(aggregate, path, args, commandTimeout, maxStdoutBytes, maxStderrBytes)
}

func (p *Probe) commandAtWithLimits(aggregate context.Context, path string, args []string, commandTimeout time.Duration, maxStdoutBytes, maxStderrBytes int) ([]byte, []byte, error, ErrorCategory) {
	commandCtx, cancel := context.WithTimeout(aggregate, commandTimeout)
	defer cancel()
	var stdout, stderr []byte
	var err error
	runner := p.Runner
	if runner != nil {
		stdout, stderr, err = runner.Run(commandCtx, path, append([]string(nil), args...), []string{"LC_ALL=C", "LANG=C"})
		if len(stdout) > maxStdoutBytes || len(stderr) > maxStderrBytes {
			return nil, nil, errOutputLimit, ErrorOutputLimit
		}
	} else {
		stdout, stderr, err = runExec(commandCtx, path, args, maxStdoutBytes, maxStderrBytes)
	}
	if err == nil {
		return stdout, stderr, nil, ""
	}
	// Keep bounded stdout available to the scheduler parser for the one
	// explicit stopped sentence that some lpstat versions emit with a
	// nonzero exit status.  Callers never copy this output into Report.
	return stdout, stderr, err, classifyError(err, commandCtx, aggregate)
}

func runExec(ctx context.Context, path string, args []string, maxStdout, maxStderr int) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	// Supplying Env explicitly avoids inheriting locale-dependent parsing
	// behavior.  No shell or PATH lookup is involved.
	command.Env = []string{"LC_ALL=C", "LANG=C"}
	var stdout, stderr limitedBuffer
	stdout.max = maxStdout
	stderr.max = maxStderr
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, nil, errOutputLimit
	}
	return stdout.data.Bytes(), stderr.data.Bytes(), err
}

var errOutputLimit = errors.New("printer: output limit")

type limitedBuffer struct {
	data     bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 || len(p) > b.max-b.data.Len() {
		b.overflow = true
		remaining := b.max - b.data.Len()
		if remaining > 0 {
			_, _ = b.data.Write(p[:remaining])
		}
		return len(p), errOutputLimit
	}
	return b.data.Write(p)
}

func classifyError(err error, commandCtx, aggregate context.Context) ErrorCategory {
	if errors.Is(err, errOutputLimit) {
		return ErrorOutputLimit
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(commandCtx.Err(), context.DeadlineExceeded) || errors.Is(aggregate.Err(), context.DeadlineExceeded) {
		return ErrorTimeout
	}
	if errors.Is(err, context.Canceled) || errors.Is(commandCtx.Err(), context.Canceled) || errors.Is(aggregate.Err(), context.Canceled) {
		return ErrorContextCanceled
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return ErrorBinaryMissing
	}
	return ErrorCommandFailed
}

func transportForCategory(category ErrorCategory) TransportState {
	switch category {
	case ErrorTimeout:
		return TransportTimeout
	case ErrorContextCanceled:
		return TransportUnknown
	case ErrorBinaryMissing, ErrorOutputLimit, ErrorCommandFailed, ErrorEnumerationInvalid, ErrorEnumerationLimit, ErrorQueueStatusFailed, ErrorQueueOutputInvalid:
		return TransportUnavailable
	default:
		return TransportUnknown
	}
}

func categoryPtr(category ErrorCategory) *ErrorCategory {
	if category == "" {
		return nil
	}
	c := category
	return &c
}

func physicalErrorPtr(category PhysicalErrorCategory) *PhysicalErrorCategory {
	if category == "" {
		return nil
	}
	c := category
	return &c
}

// ParseSchedulerOutput conservatively recognizes only the unambiguous C
// locale lpstat -r prefixes.  Any other output is unknown.
func ParseSchedulerOutput(output []byte) SchedulerState {
	line, ok := singleLine(output)
	if !ok {
		return SchedulerUnknown
	}
	line = strings.ToLower(strings.TrimSpace(line))
	switch {
	case strings.HasPrefix(line, "scheduler is not running"):
		return SchedulerStopped
	case strings.HasPrefix(line, "scheduler is running"):
		return SchedulerRunning
	default:
		return SchedulerUnknown
	}
}

// ParseQueueState recognizes CUPS lpstat -p output only when the expected
// queue name appears in the printer prefix.  “printing” is normalized to the
// UI-neutral processing state; “disabled” is stopped evidence.
func ParseQueueState(name string, output []byte) QueueState {
	if !isSafeQueueName(name) {
		return QueueUnknown
	}
	line, ok := firstQueueStatusLine(name, output)
	if !ok {
		return QueueUnknown
	}
	remainder := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(line)), "printer "+strings.ToLower(name)+" "))
	switch {
	case strings.HasPrefix(remainder, "is idle"):
		return QueueIdle
	case strings.HasPrefix(remainder, "is printing"), strings.HasPrefix(remainder, "is processing"), strings.HasPrefix(remainder, "now printing"):
		return QueueProcessing
	case strings.HasPrefix(remainder, "is stopped"), strings.HasPrefix(remainder, "disabled"):
		return QueueStopped
	default:
		return QueueUnknown
	}
}

func firstQueueStatusLine(name string, output []byte) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	first := ""
	statusPrefix := "printer " + strings.ToLower(name) + " "
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if first == "" {
			first = line
			continue
		}
		// Continuation diagnostics are tolerated, but a second printer status
		// line would make the sample ambiguous/conflicting.
		if strings.HasPrefix(strings.ToLower(line), statusPrefix) {
			return "", false
		}
	}
	if first == "" {
		return "", false
	}
	prefix := "printer " + strings.ToLower(name) + " "
	if !strings.HasPrefix(strings.ToLower(first), prefix) {
		return "", false
	}
	return first, true
}

func parseZebraUSBSerial(name string, output []byte) (string, bool) {
	if !isSafeQueueName(name) {
		return "", false
	}
	line, ok := singleLine(output)
	if !ok {
		return "", false
	}
	prefix := "device for " + strings.ToLower(name) + ":"
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, prefix) {
		return "", false
	}
	raw := strings.TrimSpace(trimmed[len(prefix):])
	if len(raw) < len("usb://") || !strings.EqualFold(raw[:len("usb://")], "usb://") || strings.Contains(raw, "#") || strings.Count(raw, "?") != 1 {
		return "", false
	}
	deviceAndQuery := raw[len("usb://"):]
	querySeparator := strings.IndexByte(deviceAndQuery, '?')
	device := deviceAndQuery[:querySeparator]
	pathSeparator := strings.IndexByte(device, '/')
	if pathSeparator <= 0 || pathSeparator == len(device)-1 {
		return "", false
	}
	manufacturer, manufacturerErr := url.PathUnescape(device[:pathSeparator])
	model, modelErr := url.PathUnescape(device[pathSeparator+1:])
	if manufacturerErr != nil || modelErr != nil || !strings.EqualFold(manufacturer, "Zebra Technologies") || !strings.Contains(strings.ToLower(model), "zd421") || strings.ContainsAny(model, "/\\") {
		return "", false
	}
	query, err := url.ParseQuery(deviceAndQuery[querySeparator+1:])
	if err != nil || len(query) != 1 || len(query["serial"]) != 1 || !safeUSBSerial(query["serial"][0]) {
		return "", false
	}
	return query["serial"][0], true
}

func safeUSBSerial(serial string) bool {
	if len(serial) == 0 || len(serial) > 64 {
		return false
	}
	for index := 0; index < len(serial); index++ {
		value := serial[index]
		if (value < 'a' || value > 'z') && (value < 'A' || value > 'Z') && (value < '0' || value > '9') && value != '.' && value != '_' && value != '-' {
			return false
		}
	}
	return true
}

// ParseDeviceTransport returns only a coarse redacted transport class. URI,
// host, and backend diagnostics never enter the report.
func ParseDeviceTransport(name string, output []byte) DeviceTransport {
	if !isSafeQueueName(name) {
		return DeviceTransportUnknown
	}
	line, ok := singleLine(output)
	if !ok {
		return DeviceTransportUnknown
	}
	prefix := "device for " + strings.ToLower(name) + ":"
	lower := strings.ToLower(strings.TrimSpace(line))
	if !strings.HasPrefix(lower, prefix) {
		return DeviceTransportUnknown
	}
	return parseDeviceTransportURI(strings.TrimSpace(line[len(prefix):]))
}

// parseDeviceTransportSnapshot maps one lpstat -v snapshot to the exact set
// of queue names returned by lpstat -e. Unknown queues, malformed lines, and
// duplicate queue records make the snapshot incomplete, but independently
// valid records remain usable so a transient extra line cannot erase a known
// USB classification. Raw lines are retained only in transportEvidence for
// the current process and are never returned by the report.
func parseDeviceTransportSnapshot(output []byte, queues []string) (map[string]transportEvidence, bool) {
	expected := make(map[string]struct{}, len(queues))
	for _, name := range queues {
		if isSafeQueueName(name) {
			expected[name] = struct{}{}
		}
	}
	evidence := make(map[string]transportEvidence, len(expected))
	if len(output) == 0 {
		return evidence, len(expected) == 0
	}

	complete := true
	seen := make(map[string]struct{}, len(expected))
	for raw := range strings.SplitSeq(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		name, transport, ok := parseDeviceTransportLine(line)
		if !ok {
			complete = false
			continue
		}
		if _, isExpected := expected[name]; !isExpected {
			// lpstat may race with queue removal and include an unenumerated
			// destination. It is not mapped or trusted for any report field.
			complete = false
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			delete(evidence, name)
			complete = false
			continue
		}
		seen[name] = struct{}{}
		evidence[name] = transportEvidence{transport: transport, line: []byte(line)}
	}
	if len(evidence) != len(expected) {
		complete = false
	}
	return evidence, complete
}

func parseDeviceTransportLine(line string) (string, DeviceTransport, bool) {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	const prefix = "device for "
	if !strings.HasPrefix(lower, prefix) {
		return "", DeviceTransportUnknown, false
	}
	remainder := trimmed[len(prefix):]
	separator := strings.IndexByte(remainder, ':')
	if separator <= 0 || strings.TrimSpace(remainder[:separator]) != remainder[:separator] {
		return "", DeviceTransportUnknown, false
	}
	name := remainder[:separator]
	if !isSafeQueueName(name) {
		return "", DeviceTransportUnknown, false
	}
	uri := strings.TrimSpace(remainder[separator+1:])
	if !validDeviceURI(uri) {
		return name, DeviceTransportUnknown, false
	}
	return name, parseDeviceTransportURI(uri), true
}

func isWellFormedDeviceTransportLine(name string, output []byte) bool {
	line, ok := singleLine(output)
	if !ok {
		return false
	}
	parsedName, _, parsed := parseDeviceTransportLine(line)
	return parsed && parsedName == name
}

func validDeviceURI(value string) bool {
	separator := strings.Index(value, "://")
	if separator <= 0 || separator == len(value)-3 {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	for index, character := range value[:separator] {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (index > 0 && ((character >= '0' && character <= '9') || character == '+' || character == '-' || character == '.')) {
			continue
		}
		return false
	}
	return true
}

func parseDeviceTransportURI(value string) DeviceTransport {
	separator := strings.Index(value, "://")
	if separator <= 0 {
		return DeviceTransportUnknown
	}
	scheme := strings.ToLower(value[:separator])
	if scheme == "usb" {
		return DeviceTransportUSB
	}
	switch scheme {
	case "ipp", "ipps", "socket", "lpd", "http", "https", "smb", "dnssd", "mdns", "implicitclass":
		return DeviceTransportNetwork
	default:
		return DeviceTransportUnknown
	}
}

// ParseQueueOptions accepts only the stable `name/label: choices` shape from
// lpoptions -l. Invalid lines are omitted independently so one vendor option
// cannot erase the remaining capability evidence.
func ParseQueueOptions(output []byte) []QueueOption {
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	options := make([]QueueOption, 0, min(len(lines), MaxQueueOptions))
	seen := make(map[string]struct{})
	for _, raw := range lines {
		if len(options) >= MaxQueueOptions {
			break
		}
		line := strings.TrimSpace(raw)
		separator := strings.IndexByte(line, ':')
		if separator <= 0 || separator == len(line)-1 {
			continue
		}
		nameAndLabel := strings.TrimSpace(line[:separator])
		name := nameAndLabel
		if before, _, ok := strings.Cut(nameAndLabel, "/"); ok {
			name = before
		}
		if !safeOptionToken(name, 64) {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		choices := make([]string, 0)
		choiceSeen := make(map[string]struct{})
		var defaultValue *string
		valid := true
		for field := range strings.FieldsSeq(line[separator+1:]) {
			isDefault := strings.HasPrefix(field, "*")
			value := strings.TrimPrefix(field, "*")
			if slash := strings.IndexByte(value, '/'); slash >= 0 {
				value = value[:slash]
			}
			if !safeOptionToken(value, 128) {
				valid = false
				break
			}
			if _, duplicate := choiceSeen[value]; duplicate {
				valid = false
				break
			}
			choiceSeen[value] = struct{}{}
			choices = append(choices, value)
			if isDefault {
				if defaultValue != nil {
					valid = false
					break
				}
				copyValue := value
				defaultValue = &copyValue
			}
			if len(choices) > MaxOptionChoices {
				valid = false
				break
			}
		}
		if !valid || len(choices) == 0 {
			continue
		}
		seen[name] = struct{}{}
		options = append(options, QueueOption{Name: name, Default: defaultValue, Choices: choices})
	}
	sort.Slice(options, func(i, j int) bool { return options[i].Name < options[j].Name })
	return options
}

func safeOptionToken(value string, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-+", character) {
			continue
		}
		return false
	}
	return true
}

// parseZebraTarget returns a redacted internal dial target only for a socket
// backend addressed by a private or link-local IP on Zebra's fixed port. DNS,
// userinfo, loopback, multicast, unspecified, public addresses, and paths are
// deliberately ineligible.
func parseZebraTarget(name string, output []byte) (string, bool) {
	if !isSafeQueueName(name) {
		return "", false
	}
	line, ok := singleLine(output)
	if !ok {
		return "", false
	}
	prefix := "device for " + strings.ToLower(name) + ":"
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, prefix) {
		return "", false
	}
	raw := strings.TrimSpace(trimmed[len(prefix):])
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socket" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	host := parsed.Hostname()
	if host == "" || net.ParseIP(host) == nil || parsed.Port() != "9100" {
		return "", false
	}
	ip := net.ParseIP(host)
	if !eligibleZebraIP(ip) {
		return "", false
	}
	return net.JoinHostPort(host, "9100"), true
}

func eligibleZebraIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return true
	}
	return ip.IsPrivate()
}

// ParseCUPSStateReasons extracts only the exact bounded CUPS reason token
// allow-list. The bool is false for a malformed/conflicting reason field;
// unrelated continuation diagnostics are ignored.
func ParseCUPSStateReasons(output []byte) ([]PhysicalReason, bool) {
	found := false
	seen := make(map[PhysicalReason]struct{})
	for raw := range strings.SplitSeq(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)
		field := ""
		for _, candidate := range []string{"printer-state-reasons:", "alerts:"} {
			if strings.HasPrefix(lower, candidate) {
				field = candidate
				break
			}
		}
		if field == "" {
			continue
		}
		if found {
			return nil, false
		}
		found = true
		value := strings.TrimSpace(line[len(field):])
		if value == "" {
			return nil, false
		}
		tokens := strings.Fields(strings.ReplaceAll(value, ",", " "))
		if len(tokens) == 0 {
			return nil, false
		}
		none := false
		for _, token := range tokens {
			token = strings.ToLower(token)
			if token == "none" {
				none = true
				continue
			}
			reason, ok := cupsPhysicalReason(token)
			if !ok {
				// CUPS and vendors may add bounded reason names. Ignore those
				// names, but never turn them into evidence or UI text.
				continue
			}
			if _, duplicate := seen[reason]; duplicate {
				return nil, false
			}
			seen[reason] = struct{}{}
		}
		if none && len(seen) > 0 {
			return nil, false
		}
	}
	reasons := make([]PhysicalReason, 0, len(seen))
	for _, reason := range cupsPhysicalReasonOrder {
		if _, ok := seen[reason]; ok {
			reasons = append(reasons, reason)
		}
	}
	return reasons, true
}

var cupsPhysicalReasonOrder = []PhysicalReason{
	PhysicalReasonMediaEmpty,
	PhysicalReasonMediaLow,
	PhysicalReasonMediaJam,
	PhysicalReasonCoverOpen,
	PhysicalReasonPaused,
	PhysicalReasonOffline,
	PhysicalReasonMarkerSupplyEmpty,
	PhysicalReasonMarkerSupplyLow,
}

func cupsPhysicalReason(token string) (PhysicalReason, bool) {
	for _, suffix := range []string{"-error", "-warning", "-report"} {
		if before, ok := strings.CutSuffix(token, suffix); ok {
			token = before
			break
		}
	}
	switch token {
	case "media-empty":
		return PhysicalReasonMediaEmpty, true
	case "media-low":
		return PhysicalReasonMediaLow, true
	case "media-jam":
		return PhysicalReasonMediaJam, true
	case "cover-open":
		return PhysicalReasonCoverOpen, true
	case "paused":
		return PhysicalReasonPaused, true
	case "offline":
		return PhysicalReasonOffline, true
	case "marker-supply-empty":
		return PhysicalReasonMarkerSupplyEmpty, true
	case "marker-supply-low":
		return PhysicalReasonMarkerSupplyLow, true
	default:
		return "", false
	}
}

type zebraStatus struct {
	paperOut, paused, bufferFull, diagnosticMode, partialFormat bool
	configurationLost, underTemperature, overTemperature        bool
	headUp, ribbonOut                                           bool
}

// parseZebraHS validates all three documented ~HS records, including numeric
// fields and binary flags, before deriving the small reason vocabulary.
func parseZebraHS(output []byte) (zebraStatus, error) {
	records, err := splitZebraRecords(output)
	if err != nil {
		return zebraStatus{}, err
	}
	first, err := parseZebraFields(records[0], []int{3, 1, 1, 4, 3, 1, 1, 1, 3, 1, 1, 1})
	if err != nil {
		return zebraStatus{}, err
	}
	second, err := parseZebraFields(records[1], []int{3, 1, 1, 1, 1, 1, 1, 1, 8, 1, 3})
	if err != nil {
		return zebraStatus{}, err
	}
	third, err := parseZebraFields(records[2], []int{4, 1})
	if err != nil {
		return zebraStatus{}, err
	}
	for _, index := range []int{1, 2, 5, 6, 7, 9, 10, 11} {
		if first[index] > 1 {
			return zebraStatus{}, errors.New("zebra flag out of range")
		}
	}
	for _, index := range []int{1, 2, 3, 4, 7, 9} {
		if second[index] > 1 {
			return zebraStatus{}, errors.New("zebra flag out of range")
		}
	}
	if second[5] > 4 || second[9] != 1 || third[1] > 1 {
		return zebraStatus{}, errors.New("zebra mode or flag out of range")
	}
	return zebraStatus{
		paperOut:          first[1] == 1,
		paused:            first[2] == 1,
		bufferFull:        first[5] == 1,
		diagnosticMode:    first[6] == 1,
		partialFormat:     first[7] == 1,
		configurationLost: first[9] == 1,
		underTemperature:  first[10] == 1,
		overTemperature:   first[11] == 1,
		headUp:            second[2] == 1,
		ribbonOut:         second[3] == 1,
	}, nil
}

func splitZebraRecords(output []byte) ([][]byte, error) {
	if len(output) == 0 || len(output) > maxZebraResponseBytes {
		return nil, errors.New("zebra response size")
	}
	framed := bytes.Contains(output, []byte{0x02}) || bytes.Contains(output, []byte{0x03})
	if framed {
		records := make([][]byte, 0, 3)
		position := 0
		for len(records) < 3 {
			if position >= len(output) || output[position] != 0x02 {
				return nil, errors.New("zebra framing")
			}
			end := bytes.IndexByte(output[position+1:], 0x03)
			if end < 0 {
				return nil, errors.New("zebra framing")
			}
			end += position + 1
			records = append(records, output[position+1:end])
			position = end + 1
			if position+2 > len(output) || output[position] != '\r' || output[position+1] != '\n' {
				return nil, errors.New("zebra framing")
			}
			position += 2
		}
		if position != len(output) {
			return nil, errors.New("zebra trailing data")
		}
		return records, nil
	}
	trimmed := strings.TrimSuffix(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 3 {
		return nil, errors.New("zebra record count")
	}
	records := make([][]byte, 3)
	for index, line := range lines {
		if line == "" || strings.ContainsAny(line, "\r\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f") {
			return nil, errors.New("zebra record")
		}
		records[index] = []byte(line)
	}
	return records, nil
}

func parseZebraFields(record []byte, widths []int) ([]uint64, error) {
	fields := strings.Split(string(record), ",")
	if len(fields) != len(widths) {
		return nil, errors.New("zebra field count")
	}
	values := make([]uint64, len(widths))
	for index, field := range fields {
		if field == "" || len(field) != widths[index] || !allDigits(field) {
			return nil, errors.New("zebra numeric field")
		}
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, errors.New("zebra numeric field")
		}
		values[index] = value
	}
	return values, nil
}

func zebraReasons(status zebraStatus) []PhysicalReason {
	reasons := make([]PhysicalReason, 0, 10)
	if status.paperOut {
		reasons = append(reasons, PhysicalReasonPaperOut)
	}
	if status.paused {
		reasons = append(reasons, PhysicalReasonPaused)
	}
	if status.bufferFull {
		reasons = append(reasons, PhysicalReasonBufferFull)
	}
	if status.diagnosticMode {
		reasons = append(reasons, PhysicalReasonDiagnosticMode)
	}
	if status.partialFormat {
		reasons = append(reasons, PhysicalReasonPartialFormat)
	}
	if status.configurationLost {
		reasons = append(reasons, PhysicalReasonConfigurationLost)
	}
	if status.underTemperature {
		reasons = append(reasons, PhysicalReasonUnderTemperature)
	}
	if status.overTemperature {
		reasons = append(reasons, PhysicalReasonOverTemperature)
	}
	if status.headUp {
		reasons = append(reasons, PhysicalReasonHeadUp)
	}
	if status.ribbonOut {
		reasons = append(reasons, PhysicalReasonRibbonOut)
	}
	return reasons
}

func (p *Probe) probeZebra(ctx context.Context, target string) (PhysicalState, []PhysicalReason, *PhysicalErrorCategory) {
	timeout := p.PhysicalTimeout
	if timeout <= 0 {
		timeout = defaultPhysicalTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := p.Dialer
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}
	connection, err := dialer(probeCtx, "tcp", target)
	if err != nil {
		return PhysicalUnknown, nil, physicalErrorPtr(physicalErrorForNetwork(err, probeCtx, false, true))
	}
	defer connection.Close()
	if err := connection.SetWriteDeadline(deadlineFor(probeCtx, timeout)); err != nil {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraWrite)
	}
	if _, err := connection.Write([]byte("~HS")); err != nil {
		return PhysicalUnknown, nil, physicalErrorPtr(physicalErrorForNetwork(err, probeCtx, true, false))
	}
	if err := connection.SetReadDeadline(deadlineFor(probeCtx, timeout)); err != nil {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraTimeout)
	}
	data, readErr := readZebraResponse(connection)
	status, parseErr := parseZebraHS(data)
	if parseErr == nil {
		reasons := zebraReasons(status)
		if len(reasons) == 0 {
			return PhysicalReady, nil, nil
		}
		return PhysicalAttention, reasons, nil
	}
	if errors.Is(readErr, errZebraOversize) {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraOversize)
	}
	if len(data) == 0 {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraNoResponse)
	}
	if readErr != nil && isTimeoutError(readErr) {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraTimeout)
	}
	return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraMalformed)
}

func (p *Probe) usbHostStatusProber() USBHostStatusProber {
	if p.USBProber != nil {
		return p.USBProber
	}
	return newUSBHostStatusProber()
}

func (p *Probe) probeZebraUSB(ctx context.Context, prober USBHostStatusProber, serial string) (PhysicalState, []PhysicalReason, *PhysicalErrorCategory) {
	timeout := p.PhysicalTimeout
	if timeout <= 0 {
		timeout = defaultPhysicalTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	data, category := prober.ProbeZebraHostStatus(probeCtx, serial, timeout)
	if category != "" {
		return PhysicalUnknown, nil, physicalErrorPtr(category)
	}
	if len(data) == 0 {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraNoResponse)
	}
	if len(data) > maxZebraResponseBytes {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraOversize)
	}
	status, err := parseZebraHS(data)
	if err != nil {
		return PhysicalUnknown, nil, physicalErrorPtr(PhysicalErrorZebraMalformed)
	}
	reasons := zebraReasons(status)
	if len(reasons) == 0 {
		return PhysicalReady, nil, nil
	}
	return PhysicalAttention, reasons, nil
}

var errZebraOversize = errors.New("zebra response exceeds bound")

func readZebraResponse(connection net.Conn) ([]byte, error) {
	data := make([]byte, 0, maxZebraResponseBytes)
	buffer := make([]byte, 512)
	for {
		count, err := connection.Read(buffer)
		if count > 0 {
			if len(data)+count > maxZebraResponseBytes {
				return nil, errZebraOversize
			}
			data = append(data, buffer[:count]...)
			// Zebra raw-port connections commonly remain open after replying to
			// ~HS.  A complete, exact response is enough evidence; waiting for
			// EOF would spend the full physical probe timeout for every queue.
			// parseZebraHS also rejects trailing bytes already received in this
			// read, while bytes arriving later are intentionally not awaited.
			if _, parseErr := parseZebraHS(data); parseErr == nil {
				return data, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return data, nil
			}
			return data, err
		}
	}
}

func deadlineFor(ctx context.Context, fallback time.Duration) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(fallback)
}

func isTimeoutError(err error) bool {
	var networkErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkErr) && networkErr.Timeout()
}

func physicalErrorForNetwork(err error, ctx context.Context, write, connect bool) PhysicalErrorCategory {
	if isTimeoutError(err) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return PhysicalErrorZebraTimeout
	}
	if connect {
		return PhysicalErrorZebraConnect
	}
	if write {
		return PhysicalErrorZebraWrite
	}
	return PhysicalErrorZebraMalformed
}

// ParseAcceptingJobs recognizes one CUPS lpstat -a header and discards its
// indented rejection reason.
func ParseAcceptingJobs(name string, output []byte) AcceptingState {
	if !isSafeQueueName(name) || len(output) == 0 || len(output) > defaultStdoutBytes {
		return AcceptingUnknown
	}
	text := strings.TrimSuffix(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	if strings.ContainsAny(text, "\r\x00") {
		return AcceptingUnknown
	}
	line, details, hasDetails := strings.Cut(text, "\n")
	if line == "" || strings.TrimSpace(line) != line {
		return AcceptingUnknown
	}
	line = strings.ToLower(line)
	prefix := strings.ToLower(name) + " "
	if !strings.HasPrefix(line, prefix) {
		return AcceptingUnknown
	}
	status, since, hasSince := strings.Cut(strings.TrimPrefix(line, prefix), " since ")
	if hasSince && strings.TrimSpace(since) == "" {
		return AcceptingUnknown
	}
	state := AcceptingUnknown
	switch status {
	case "not accepting requests":
		state = AcceptingNo
	case "accepting requests":
		state = AcceptingYes
	}
	if hasDetails {
		if state != AcceptingNo {
			return AcceptingUnknown
		}
		for detail := range strings.SplitSeq(details, "\n") {
			if !strings.HasPrefix(detail, "\t") || strings.TrimSpace(detail) == "" {
				return AcceptingUnknown
			}
		}
	}
	return state
}

// ParseActiveJobs returns a count only when every non-empty line is an
// unambiguous CUPS job record beginning with queue-<decimal-job-id>.  A
// successful empty output returns a non-nil pointer to zero.
func ParseActiveJobs(name string, output []byte) *int {
	if !isSafeQueueName(name) {
		return nil
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		zero := 0
		return &zero
	}
	count := 0
	for raw := range strings.SplitSeq(trimmed, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil
		}
		job := fields[0]
		prefix := name + "-"
		if !strings.HasPrefix(job, prefix) || len(job) == len(prefix) || !allDigits(job[len(prefix):]) {
			return nil
		}
		count++
		if count > 1_000_000 {
			return nil
		}
	}
	result := count
	return &result
}

func singleLine(output []byte) (string, bool) {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" || strings.Contains(trimmed, "\n") {
		return "", false
	}
	return strings.TrimSuffix(trimmed, "\r"), true
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isSafeQueueName(name string) bool {
	if len(name) == 0 || len(name) > MaxQueueNameBytes {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func parseQueueEnumeration(output []byte) ([]string, ErrorCategory) {
	if len(output) == 0 {
		return []string{}, ""
	}
	seen := make(map[string]struct{}, MaxQueues)
	queues := make([]string, 0, MaxQueues)
	category := ErrorCategory("")
	lines := strings.SplitSeq(strings.TrimSuffix(string(output), "\n"), "\n")
	for raw := range lines {
		name := strings.TrimSuffix(raw, "\r")
		if name == "" {
			category = firstCategory(category, ErrorEnumerationInvalid)
			continue
		}
		if !isSafeQueueName(name) {
			category = firstCategory(category, ErrorEnumerationInvalid)
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		queues = append(queues, name)
	}
	sort.Strings(queues)
	if len(queues) > MaxQueues {
		category = firstCategory(category, ErrorEnumerationLimit)
		queues = queues[:MaxQueues]
	}
	return queues, category
}

func firstCategory(current, next ErrorCategory) ErrorCategory {
	if current != "" {
		return current
	}
	return next
}

// Validate strictly checks the bounded report shape, enum vocabulary, queue
// names, timestamps, duplicate names, and JSON size.  Queue order is not a
// validity concern; canonicalization sorts a copy before hashing.
func Validate(report Report) error {
	if report.USBDiscovery != nil && !validUSBDiscovery(*report.USBDiscovery) {
		return errors.New("printer: invalid USB discovery")
	}
	if report.Version != Version {
		return fmt.Errorf("printer: unsupported version")
	}
	if report.Type != Type || report.Source != Source {
		return fmt.Errorf("printer: invalid type or source")
	}
	if err := validateTimestamp(report.ObservedAt); err != nil {
		return fmt.Errorf("printer: observedAt: %w", err)
	}
	if !validScheduler(report.Scheduler) {
		return fmt.Errorf("printer: invalid scheduler")
	}
	if !validTransport(report.Transport) {
		return fmt.Errorf("printer: invalid transport")
	}
	if report.ErrorCategory != nil && !validErrorCategory(*report.ErrorCategory) {
		return fmt.Errorf("printer: invalid errorCategory")
	}
	if len(report.Queues) > MaxQueues {
		return fmt.Errorf("printer: too many queues")
	}
	seen := make(map[string]struct{}, len(report.Queues))
	for index, queue := range report.Queues {
		if !isSafeQueueName(queue.Name) {
			return fmt.Errorf("printer: queue %d has invalid name", index)
		}
		if _, exists := seen[queue.Name]; exists {
			return fmt.Errorf("printer: duplicate queue name")
		}
		seen[queue.Name] = struct{}{}
		if !validQueueState(queue.QueueState) || !validAccepting(queue.AcceptingJobs) || !validPhysicalState(queue.PhysicalState) || !validDeviceTransport(queue.DeviceTransport) || !validPhysicalSource(queue.PhysicalSource) {
			return fmt.Errorf("printer: queue %q has invalid state", queue.Name)
		}
		if queue.ErrorCategory != nil && !validQueueErrorCategory(*queue.ErrorCategory) {
			return fmt.Errorf("printer: queue %q has invalid errorCategory", queue.Name)
		}
		if queue.ActiveJobs != nil && (*queue.ActiveJobs < 0 || *queue.ActiveJobs > 1_000_000) {
			return fmt.Errorf("printer: queue %q has invalid activeJobs", queue.Name)
		}
		if err := validatePhysicalEvidence(&queue); err != nil {
			return fmt.Errorf("printer: queue %q physical evidence: %w", queue.Name, err)
		}
		if err := validateTimestamp(queue.SampledAt); err != nil {
			return fmt.Errorf("printer: queue %q sampledAt: %w", queue.Name, err)
		}
		if err := validateQueueOptions(queue.Options); err != nil {
			return fmt.Errorf("printer: queue %q options: %w", queue.Name, err)
		}
		if queue.CustomMedia != nil && !validCustomMediaBounds(*queue.CustomMedia) {
			return fmt.Errorf("printer: queue %q custom media bounds invalid", queue.Name)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("printer: marshal report: %w", err)
	}
	if len(encoded) > MaxReportBytes {
		return fmt.Errorf("%w: report exceeds %d bytes", errReportSize, MaxReportBytes)
	}
	return nil
}

// Validate is also available as a method for integration code.
func (r Report) Validate() error { return Validate(r) }

// Normalize validates a report and returns a copy with queue order sorted by
// name and timestamps represented in canonical UTC RFC3339Nano form.
func Normalize(report Report) (Report, error) {
	if err := Validate(report); err != nil {
		return Report{}, err
	}
	normalized := report
	normalized.ObservedAt = canonicalTimestamp(report.ObservedAt)
	normalized.Queues = append([]QueueReport(nil), report.Queues...)
	for index := range normalized.Queues {
		normalized.Queues[index].SampledAt = canonicalTimestamp(normalized.Queues[index].SampledAt)
		normalized.Queues[index].Options = normalizeQueueOptions(normalized.Queues[index].Options)
	}
	sort.SliceStable(normalized.Queues, func(i, j int) bool { return normalized.Queues[i].Name < normalized.Queues[j].Name })
	return normalized, nil
}

func validateQueueOptions(options []QueueOption) error {
	if len(options) > MaxQueueOptions {
		return errors.New("too many options")
	}
	seen := make(map[string]struct{}, len(options))
	for _, option := range options {
		if !safeOptionToken(option.Name, 64) || len(option.Choices) == 0 || len(option.Choices) > MaxOptionChoices {
			return errors.New("invalid option")
		}
		if _, duplicate := seen[option.Name]; duplicate {
			return errors.New("duplicate option")
		}
		seen[option.Name] = struct{}{}
		choices := make(map[string]struct{}, len(option.Choices))
		for _, choice := range option.Choices {
			if !safeOptionToken(choice, 128) {
				return errors.New("invalid choice")
			}
			if _, duplicate := choices[choice]; duplicate {
				return errors.New("duplicate choice")
			}
			choices[choice] = struct{}{}
		}
		if option.Default != nil {
			if _, present := choices[*option.Default]; !present {
				return errors.New("default is not advertised")
			}
		}
	}
	return nil
}

func validCustomMediaBounds(bounds CustomMediaBounds) bool {
	if bounds.Unit != "mm" || !finiteNumber(bounds.MinWidthMM) || !finiteNumber(bounds.MaxWidthMM) || !finiteNumber(bounds.MinHeightMM) || !finiteNumber(bounds.MaxHeightMM) || bounds.MinWidthMM < 12.7 || bounds.MaxWidthMM > 203.2 || bounds.MinWidthMM > bounds.MaxWidthMM || bounds.MinHeightMM < 12.7 || bounds.MaxHeightMM > 1270 || bounds.MinHeightMM > bounds.MaxHeightMM || (bounds.DefaultWidthMM == nil) != (bounds.DefaultHeightMM == nil) {
		return false
	}
	return bounds.DefaultWidthMM == nil || hundredthMM(*bounds.DefaultWidthMM) && hundredthMM(*bounds.DefaultHeightMM) && *bounds.DefaultWidthMM >= bounds.MinWidthMM && *bounds.DefaultWidthMM <= bounds.MaxWidthMM && *bounds.DefaultHeightMM >= bounds.MinHeightMM && *bounds.DefaultHeightMM <= bounds.MaxHeightMM
}

func finiteNumber(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func normalizeQueueOptions(options []QueueOption) []QueueOption {
	if len(options) == 0 {
		return nil
	}
	normalized := make([]QueueOption, len(options))
	for index, option := range options {
		normalized[index] = option
		normalized[index].Choices = append([]string(nil), option.Choices...)
		sort.Strings(normalized[index].Choices)
		if option.Default != nil {
			value := *option.Default
			normalized[index].Default = &value
		}
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Name < normalized[j].Name })
	return normalized
}

func validateTimestamp(value string) error {
	if value == "" || len(value) > 64 {
		return errors.New("must be RFC3339 timestamp")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return errors.New("must be RFC3339 timestamp")
	}
	return nil
}

func canonicalTimestamp(value string) string {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed.UTC().Format(time.RFC3339Nano)
}

func validScheduler(state SchedulerState) bool {
	return state == SchedulerRunning || state == SchedulerStopped || state == SchedulerUnknown
}

func validTransport(state TransportState) bool {
	return state == TransportReachable || state == TransportUnavailable || state == TransportTimeout || state == TransportUnknown
}

func validQueueState(state QueueState) bool {
	return state == QueueIdle || state == QueueProcessing || state == QueueStopped || state == QueueUnknown
}

func validAccepting(state AcceptingState) bool {
	return state == AcceptingYes || state == AcceptingNo || state == AcceptingUnknown
}

func validDeviceTransport(state DeviceTransport) bool {
	return state == "" || state == DeviceTransportUSB || state == DeviceTransportNetwork || state == DeviceTransportUnknown
}

func validPhysicalState(state PhysicalState) bool {
	return state == PhysicalUnknown || state == PhysicalReady || state == PhysicalAttention
}

func validPhysicalSource(source PhysicalSource) bool {
	return source == "" || isZebraPhysicalSource(source) || source == PhysicalSourceCUPS
}

func isZebraPhysicalSource(source PhysicalSource) bool {
	return source == PhysicalSourceZebraTCP || source == PhysicalSourceZebraUSB
}

func validPhysicalReason(reason PhysicalReason) bool {
	switch reason {
	case PhysicalReasonPaperOut, PhysicalReasonPaused, PhysicalReasonBufferFull, PhysicalReasonDiagnosticMode,
		PhysicalReasonPartialFormat, PhysicalReasonConfigurationLost, PhysicalReasonUnderTemperature,
		PhysicalReasonOverTemperature, PhysicalReasonHeadUp, PhysicalReasonRibbonOut, PhysicalReasonMediaEmpty,
		PhysicalReasonMediaLow, PhysicalReasonMediaJam, PhysicalReasonCoverOpen, PhysicalReasonOffline,
		PhysicalReasonMarkerSupplyEmpty, PhysicalReasonMarkerSupplyLow:
		return true
	default:
		return false
	}
}

func validPhysicalErrorCategory(category PhysicalErrorCategory) bool {
	switch category {
	case PhysicalErrorZebraConnect, PhysicalErrorZebraWrite, PhysicalErrorZebraTimeout,
		PhysicalErrorZebraNoResponse, PhysicalErrorZebraMalformed, PhysicalErrorZebraOversize,
		PhysicalErrorZebraUSBUnavailable, PhysicalErrorZebraUSBPermission, PhysicalErrorZebraUSBBusy,
		PhysicalErrorCUPSUnavailable, PhysicalErrorCUPSInvalid:
		return true
	default:
		return false
	}
}

func physicalReasonBelongsToSource(source PhysicalSource, reason PhysicalReason) bool {
	if isZebraPhysicalSource(source) {
		switch reason {
		case PhysicalReasonPaperOut, PhysicalReasonPaused, PhysicalReasonBufferFull, PhysicalReasonDiagnosticMode,
			PhysicalReasonPartialFormat, PhysicalReasonConfigurationLost, PhysicalReasonUnderTemperature,
			PhysicalReasonOverTemperature, PhysicalReasonHeadUp, PhysicalReasonRibbonOut:
			return true
		default:
			return false
		}
	}
	if source == PhysicalSourceCUPS {
		switch reason {
		case PhysicalReasonMediaEmpty, PhysicalReasonMediaLow, PhysicalReasonMediaJam, PhysicalReasonCoverOpen,
			PhysicalReasonPaused, PhysicalReasonOffline, PhysicalReasonMarkerSupplyEmpty, PhysicalReasonMarkerSupplyLow:
			return true
		default:
			return false
		}
	}
	return false
}

func physicalErrorBelongsToSource(source PhysicalSource, category PhysicalErrorCategory) bool {
	if isZebraPhysicalSource(source) {
		if category == PhysicalErrorZebraUSBUnavailable || category == PhysicalErrorZebraUSBPermission || category == PhysicalErrorZebraUSBBusy {
			return source == PhysicalSourceZebraUSB
		}
		return category == PhysicalErrorZebraConnect || category == PhysicalErrorZebraWrite || category == PhysicalErrorZebraTimeout || category == PhysicalErrorZebraNoResponse || category == PhysicalErrorZebraMalformed || category == PhysicalErrorZebraOversize
	}
	if source == PhysicalSourceCUPS {
		return category == PhysicalErrorCUPSUnavailable || category == PhysicalErrorCUPSInvalid
	}
	return false
}

func validatePhysicalEvidence(queue *QueueReport) error {
	if queue.PhysicalErrorCategory != nil && !validPhysicalErrorCategory(*queue.PhysicalErrorCategory) {
		return errors.New("invalid physicalErrorCategory")
	}
	seen := make(map[PhysicalReason]struct{}, len(queue.PhysicalReasons))
	for _, reason := range queue.PhysicalReasons {
		if !validPhysicalReason(reason) {
			return errors.New("invalid physicalReasons")
		}
		if _, exists := seen[reason]; exists {
			return errors.New("duplicate physicalReasons")
		}
		if !physicalReasonBelongsToSource(queue.PhysicalSource, reason) {
			return errors.New("physicalReasons do not match source")
		}
		seen[reason] = struct{}{}
	}
	if queue.PhysicalSource == "" && queue.PhysicalErrorCategory != nil {
		return errors.New("physicalErrorCategory requires source")
	}
	if queue.PhysicalErrorCategory != nil && !physicalErrorBelongsToSource(queue.PhysicalSource, *queue.PhysicalErrorCategory) {
		return errors.New("physicalErrorCategory does not match source")
	}
	switch queue.PhysicalState {
	case PhysicalUnknown:
		if len(queue.PhysicalReasons) != 0 {
			return errors.New("unknown state cannot include reasons")
		}
		if isZebraPhysicalSource(queue.PhysicalSource) && queue.PhysicalErrorCategory == nil {
			return errors.New("unknown Zebra state requires an error")
		}
	case PhysicalReady:
		if !isZebraPhysicalSource(queue.PhysicalSource) || len(queue.PhysicalReasons) != 0 || queue.PhysicalErrorCategory != nil {
			return errors.New("ready state requires clean Zebra evidence")
		}
	case PhysicalAttention:
		if queue.PhysicalSource == "" || len(queue.PhysicalReasons) == 0 || queue.PhysicalErrorCategory != nil {
			return errors.New("attention state requires reasons and source")
		}
	}
	return nil
}

func validQueueErrorCategory(category ErrorCategory) bool {
	return category == ErrorBinaryMissing || category == ErrorTimeout || category == ErrorContextCanceled || category == ErrorOutputLimit || category == ErrorCommandFailed || category == ErrorQueueStatusFailed || category == ErrorQueueOutputInvalid
}

func validErrorCategory(category ErrorCategory) bool {
	switch category {
	case ErrorBinaryMissing, ErrorTimeout, ErrorContextCanceled, ErrorOutputLimit, ErrorCommandFailed, ErrorEnumerationInvalid, ErrorEnumerationLimit, ErrorQueueStatusFailed, ErrorQueueOutputInvalid:
		return true
	default:
		return false
	}
}

// Marshal validates and serializes a report under the hard payload bound.
func Marshal(report Report) ([]byte, error) {
	if err := Validate(report); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// CanonicalPayload returns the bounded printer-report-canonical-v1 payload
// for hashing and signing. Queue records are sorted by name and bind state,
// transport, physical evidence, complete option records and custom media.
// Strings and structured capability records use raw URL-base64 encoding.
func CanonicalPayload(report Report) ([]byte, error) {
	normalized, err := Normalize(report)
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("printer-report-canonical-v1\n")
	writeCanonicalField(&builder, "version", strconv.Itoa(normalized.Version))
	writeCanonicalField(&builder, "type", normalized.Type)
	writeCanonicalField(&builder, "source", normalized.Source)
	writeCanonicalField(&builder, "observedAt", normalized.ObservedAt)
	writeCanonicalField(&builder, "scheduler", string(normalized.Scheduler))
	writeCanonicalField(&builder, "transport", string(normalized.Transport))
	if normalized.ErrorCategory == nil {
		writeCanonicalField(&builder, "errorCategory", "")
	} else {
		writeCanonicalField(&builder, "errorCategory", string(*normalized.ErrorCategory))
	}
	writeCanonicalField(&builder, "queueCount", strconv.Itoa(len(normalized.Queues)))
	for _, queue := range normalized.Queues {
		active := "null"
		if queue.ActiveJobs != nil {
			active = strconv.Itoa(*queue.ActiveJobs)
		}
		builder.WriteString("queue=")
		builder.WriteString(encodeCanonical(queue.Name))
		builder.WriteByte('\t')
		builder.WriteString(string(queue.QueueState))
		builder.WriteByte('\t')
		builder.WriteString(string(queue.AcceptingJobs))
		builder.WriteByte('\t')
		builder.WriteString(active)
		builder.WriteByte('\t')
		builder.WriteString(string(queue.PhysicalState))
		builder.WriteString("\t")
		if queue.DeviceTransport != "" {
			builder.WriteString(string(queue.DeviceTransport))
			builder.WriteByte('\t')
		}
		if queue.ErrorCategory != nil {
			builder.WriteString(string(*queue.ErrorCategory))
			builder.WriteByte('\t')
		}
		if queue.PhysicalSource != "" {
			builder.WriteString(string(queue.PhysicalSource))
			builder.WriteByte('\t')
		}
		if len(queue.PhysicalReasons) > 0 {
			reasons := append([]PhysicalReason(nil), queue.PhysicalReasons...)
			slices.Sort(reasons)
			builder.WriteString(strings.Join(physicalReasonStrings(reasons), ","))
			builder.WriteByte('\t')
		}
		if queue.PhysicalErrorCategory != nil {
			builder.WriteString(string(*queue.PhysicalErrorCategory))
			builder.WriteByte('\t')
		}
		builder.WriteString(encodeCanonical(queue.SampledAt))
		if len(queue.Options) > 0 {
			encodedOptions, marshalErr := json.Marshal(normalizeQueueOptions(queue.Options))
			if marshalErr != nil {
				return nil, errors.New("printer: encode queue options")
			}
			builder.WriteString("\toptions=")
			builder.WriteString(encodeCanonical(string(encodedOptions)))
		}
		if queue.CustomMedia != nil {
			encodedMedia, marshalErr := json.Marshal(queue.CustomMedia)
			if marshalErr != nil {
				return nil, errors.New("printer: encode custom media")
			}
			builder.WriteString("\tcustomMedia=")
			builder.WriteString(encodeCanonical(string(encodedMedia)))
		}
		builder.WriteByte('\n')
	}
	if normalized.USBDiscovery != nil {
		writeUSBCanonical(&builder, *normalized.USBDiscovery)
	}
	canonical := []byte(builder.String())
	if len(canonical) > MaxReportBytes {
		return nil, fmt.Errorf("%w: canonical payload exceeds %d bytes", errReportSize, MaxReportBytes)
	}
	return canonical, nil
}

func physicalReasonStrings(reasons []PhysicalReason) []string {
	values := make([]string, len(reasons))
	for index, reason := range reasons {
		values[index] = string(reason)
	}
	return values
}

func writeCanonicalField(builder *strings.Builder, name, value string) {
	builder.WriteString(name)
	builder.WriteByte('=')
	builder.WriteString(encodeCanonical(value))
	builder.WriteByte('\n')
}

func encodeCanonical(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

// CanonicalPayloadHash returns the lowercase SHA-256 digest of
// CanonicalPayload.
func CanonicalPayloadHash(report Report) (string, error) {
	payload, err := CanonicalPayload(report)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
