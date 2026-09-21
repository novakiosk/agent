package printer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	StatisticsVersion                       = 1
	StatisticsType                          = "printer.statistics"
	StatisticsSource                        = "local-cups-lpstat-v1"
	StatisticsMaxJobs                       = 256
	StatisticsMaxQueueNameBytes             = 127
	StatisticsMaxOutputBytes                = 64 * 1024
	StatisticsMaxMessageBytes               = 64 * 1024
	StatisticsMaxJobID               uint64 = 2_147_483_647
	StatisticsMaxSizeBytes           uint64 = 1 << 40
	StatisticsMaxCompletionTextBytes        = 256
	statisticsCommandTimeout                = 5 * time.Second
)

// StatisticsErrorCategory is intentionally small and redacted. The raw
// lpstat output, user, title, and completion text never leave this package.
type StatisticsErrorCategory string

const (
	StatisticsErrorBinaryMissing   StatisticsErrorCategory = "binary_missing"
	StatisticsErrorTimeout         StatisticsErrorCategory = "timeout"
	StatisticsErrorContextCanceled StatisticsErrorCategory = "context_canceled"
	StatisticsErrorOutputLimit     StatisticsErrorCategory = "output_limit"
	StatisticsErrorCommandFailed   StatisticsErrorCategory = "command_failed"
	StatisticsErrorMalformed       StatisticsErrorCategory = "statistics_output_invalid"
	StatisticsErrorJobLimit        StatisticsErrorCategory = "statistics_job_limit"
)

type StatisticsJob struct {
	QueueName   string `json:"queueName"`
	JobKey      string `json:"jobKey"`
	CUPSJobID   uint64 `json:"cupsJobId"`
	SizeBytes   uint64 `json:"sizeBytes"`
	CompletedAt string `json:"completedAt"`
}

type Statistics struct {
	Version       int                      `json:"version"`
	Type          string                   `json:"type"`
	Source        string                   `json:"source"`
	ObservedAt    string                   `json:"observedAt"`
	ErrorCategory *StatisticsErrorCategory `json:"errorCategory"`
	Truncated     bool                     `json:"truncated"`
	Jobs          []StatisticsJob          `json:"jobs"`
}

type StatisticsConfig struct {
	Runner         Runner
	Clock          func() time.Time
	Path           string
	CommandTimeout time.Duration
	MaxOutputBytes int
}

type StatisticsProbe struct {
	runner         Runner
	clock          func() time.Time
	path           string
	commandTimeout time.Duration
	maxOutputBytes int
}

func NewStatisticsProbe(config ...StatisticsConfig) *StatisticsProbe {
	c := StatisticsConfig{}
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
	timeout := c.CommandTimeout
	if timeout <= 0 {
		timeout = statisticsCommandTimeout
	}
	maxOutput := c.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = StatisticsMaxOutputBytes
	} else if maxOutput > StatisticsMaxOutputBytes {
		maxOutput = StatisticsMaxOutputBytes
	}
	return &StatisticsProbe{runner: c.Runner, clock: clock, path: path, commandTimeout: timeout, maxOutputBytes: maxOutput}
}

func (p *StatisticsProbe) Collect(ctx context.Context) (Statistics, error) {
	if p == nil {
		return Statistics{}, errors.New("printer statistics: nil probe")
	}
	if ctx == nil {
		return Statistics{}, errors.New("printer statistics: nil context")
	}
	now := p.clock()
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	result := Statistics{Version: StatisticsVersion, Type: StatisticsType, Source: StatisticsSource, ObservedAt: now.Format(time.RFC3339Nano), ErrorCategory: nil, Truncated: false, Jobs: make([]StatisticsJob, 0)}
	commandCtx, cancel := context.WithTimeout(ctx, p.commandTimeout)
	defer cancel()
	stdout, _, err, category := p.run(commandCtx)
	if err != nil {
		result.ErrorCategory = statisticsCategoryPtr(category)
		result.Truncated = category == StatisticsErrorOutputLimit
		if category == StatisticsErrorContextCanceled && ctx.Err() == nil {
			result.ErrorCategory = statisticsCategoryPtr(StatisticsErrorTimeout)
			result.Truncated = true
		}
		return result, nil
	}
	jobs, parseCategory, truncated := ParseStatisticsOutput(stdout)
	result.Jobs = jobs
	result.Truncated = truncated
	if parseCategory != "" {
		result.ErrorCategory = statisticsCategoryPtr(parseCategory)
	}
	return result, nil
}

func (p *StatisticsProbe) run(ctx context.Context) ([]byte, []byte, error, StatisticsErrorCategory) {
	path := p.path
	max := p.maxOutputBytes
	if p.runner != nil {
		stdout, stderr, err := p.runner.Run(ctx, path, []string{"-W", "successful", "-o"}, []string{"LC_ALL=C", "LANG=C", "TZ=UTC"})
		if len(stdout) > max || len(stderr) > max {
			return nil, nil, errors.New("printer statistics: output limit"), StatisticsErrorOutputLimit
		}
		if err == nil {
			return stdout, stderr, nil, ""
		}
		return stdout, stderr, err, classifyStatisticsError(err, ctx)
	}
	command := exec.CommandContext(ctx, path, "-W", "successful", "-o")
	command.Env = []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = max, max
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, nil, errOutputLimit, StatisticsErrorOutputLimit
	}
	if err == nil {
		return stdout.data.Bytes(), stderr.data.Bytes(), nil, ""
	}
	return stdout.data.Bytes(), stderr.data.Bytes(), err, classifyStatisticsError(err, ctx)
}

func classifyStatisticsError(err error, ctx context.Context) StatisticsErrorCategory {
	if errors.Is(err, errOutputLimit) {
		return StatisticsErrorOutputLimit
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return StatisticsErrorTimeout
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return StatisticsErrorContextCanceled
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return StatisticsErrorBinaryMissing
	}
	return StatisticsErrorCommandFailed
}

func statisticsCategoryPtr(category StatisticsErrorCategory) *StatisticsErrorCategory {
	if category == "" {
		return nil
	}
	c := category
	return &c
}

var statisticsJobToken = regexp.MustCompile(`^([A-Za-z0-9._-]+)-([0-9]+)$`)

const statisticsFitObservedAt = "9999-12-31T23:59:59.999999999Z"

func fitStatisticsJobs(jobs []StatisticsJob, category StatisticsErrorCategory, truncated bool) ([]StatisticsJob, StatisticsErrorCategory, bool) {
	ranked := append([]StatisticsJob(nil), jobs...)
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].CUPSJobID != ranked[j].CUPSJobID {
			return ranked[i].CUPSJobID > ranked[j].CUPSJobID
		}
		return canonicalJobLess(ranked[i], ranked[j])
	})
	selected := ranked
	limited := truncated
	if len(selected) > StatisticsMaxJobs {
		selected = selected[:StatisticsMaxJobs]
		limited = true
	}
	if limited {
		category = StatisticsErrorJobLimit
	}
	for {
		candidate := Statistics{Version: StatisticsVersion, Type: StatisticsType, Source: StatisticsSource, ObservedAt: statisticsFitObservedAt, ErrorCategory: statisticsCategoryPtr(category), Truncated: limited, Jobs: append(make([]StatisticsJob, 0, len(selected)), selected...)}
		if _, err := candidate.MarshalBounded(); err == nil {
			if _, err = StatisticsCanonicalPayload(candidate); err == nil {
				sort.Slice(candidate.Jobs, func(i, j int) bool { return canonicalJobLess(candidate.Jobs[i], candidate.Jobs[j]) })
				return candidate.Jobs, category, limited
			}
		}
		if len(selected) == 0 {
			return []StatisticsJob{}, StatisticsErrorJobLimit, true
		}
		selected = selected[:len(selected)-1]
		limited = true
		category = StatisticsErrorJobLimit
	}
}

// ParseStatisticsOutput strictly parses CUPS lpstat -W successful -o output.
// Completion text contributes to the stable job key; user names are discarded.
func ParseStatisticsOutput(output []byte) ([]StatisticsJob, StatisticsErrorCategory, bool) {
	if len(output) > StatisticsMaxOutputBytes {
		return []StatisticsJob{}, StatisticsErrorOutputLimit, true
	}
	lines := bytes.Split(bytes.ReplaceAll(output, []byte("\r\n"), []byte("\n")), []byte("\n"))
	jobs := make([]StatisticsJob, 0, min(len(lines), StatisticsMaxJobs))
	seen := make(map[string]struct{})
	for _, raw := range lines {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return []StatisticsJob{}, StatisticsErrorMalformed, false
		}
		match := statisticsJobToken.FindStringSubmatch(fields[0])
		if match == nil || len(match[1]) > StatisticsMaxQueueNameBytes || !safeStatisticsQueueName(match[1]) {
			return []StatisticsJob{}, StatisticsErrorMalformed, false
		}
		jobID, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil || jobID == 0 || jobID > StatisticsMaxJobID {
			return []StatisticsJob{}, StatisticsErrorMalformed, false
		}
		size, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil || size > StatisticsMaxSizeBytes {
			return []StatisticsJob{}, StatisticsErrorMalformed, false
		}
		completionText := strings.Join(fields[3:], " ")
		user := fields[1]
		if len(user) == 0 || len(user) > 128 || hasStatisticsControl(user) || len(completionText) == 0 || len(completionText) > StatisticsMaxCompletionTextBytes || hasStatisticsControl(completionText) {
			return []StatisticsJob{}, StatisticsErrorMalformed, false
		}
		completedAt, parseErr := parseCUPSTimestamp(completionText)
		if parseErr != nil {
			return []StatisticsJob{}, StatisticsErrorMalformed, false
		}
		key := StatisticsJobKey(match[1], jobID, size, completionText)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		jobs = append(jobs, StatisticsJob{QueueName: match[1], JobKey: key, CUPSJobID: jobID, SizeBytes: size, CompletedAt: completedAt})
	}
	return fitStatisticsJobs(jobs, "", false)
}

func canonicalJobLess(left, right StatisticsJob) bool {
	if left.QueueName != right.QueueName {
		return left.QueueName < right.QueueName
	}
	if left.CUPSJobID != right.CUPSJobID {
		return left.CUPSJobID < right.CUPSJobID
	}
	if left.SizeBytes != right.SizeBytes {
		return left.SizeBytes < right.SizeBytes
	}
	return left.JobKey < right.JobKey
}

func hasStatisticsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func safeStatisticsQueueName(name string) bool {
	return len(name) >= 1 && len(name) <= StatisticsMaxQueueNameBytes && statisticsQueueNamePattern.MatchString(name)
}

var statisticsQueueNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func StatisticsJobKey(queue string, id, size uint64, completionText string) string {
	// Preserve the established key calculation: the normalized C-locale text
	// remains the identity input while the parsed UTC value is additive.
	encoded := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	canonical := strings.Join([]string{"printer-statistics-job-key-v1", "queue=" + encoded(queue), "cupsJobId=" + strconv.FormatUint(id, 10), "sizeBytes=" + strconv.FormatUint(size, 10), "completedAt=" + encoded(strings.Join(strings.Fields(completionText), " "))}, "\n") + "\n"
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

var activeTimestampPattern = regexp.MustCompile(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2})(?: (UTC|[+-]\d{2}:?\d{2}))?$`)
var activeTimestamp12Pattern = regexp.MustCompile(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{1,2}):(\d{2}):(\d{2}) (AM|PM)(?: (UTC|[+-]\d{2}:?\d{2}))?$`)

var statisticsCompletionPattern = regexp.MustCompile(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?: (UTC|[+-]\d{2}:?\d{2}))?(?: (AM|PM))? (\d{4})$`)
var statisticsCompletion12Pattern = regexp.MustCompile(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{1,2}) (\d{1,2}):(\d{2}):(\d{2}) (AM|PM)(?: (UTC|[+-]\d{2}:?\d{2}))? (\d{4})$`)

// parseCUPSTimestamp validates lpstat date fields and returns UTC RFC3339.
func parseCUPSTimestamp(raw string) (string, error) {
	text := strings.Join(strings.Fields(raw), " ")
	type parts struct{ weekday, month, day, hour, minute, second, meridiem, zone, year string }
	var p parts
	if m := statisticsCompletionPattern.FindStringSubmatch(text); m != nil {
		p = parts{m[1], m[2], m[3], m[4], m[5], m[6], m[8], m[7], m[9]}
	} else if m := statisticsCompletion12Pattern.FindStringSubmatch(text); m != nil {
		p = parts{m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9]}
	} else if m := activeTimestampPattern.FindStringSubmatch(text); m != nil {
		p = parts{m[1], m[3], m[2], m[5], m[6], m[7], "", m[8], m[4]}
	} else if m := activeTimestamp12Pattern.FindStringSubmatch(text); m != nil {
		p = parts{m[1], m[3], m[2], m[5], m[6], m[7], m[8], m[9], m[4]}
	} else {
		return "", errors.New("unsupported CUPS timestamp")
	}
	months := map[string]time.Month{"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April, "May": time.May, "Jun": time.June, "Jul": time.July, "Aug": time.August, "Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December}
	month, ok := months[p.month]
	if !ok {
		return "", errors.New("invalid CUPS month")
	}
	day, err := strconv.Atoi(strings.TrimSpace(p.day))
	if err != nil {
		return "", errors.New("invalid CUPS day")
	}
	year, err := strconv.Atoi(p.year)
	if err != nil || year < 1970 || year > 9999 {
		return "", errors.New("invalid CUPS year")
	}
	hour, err := strconv.Atoi(p.hour)
	if err != nil {
		return "", errors.New("invalid CUPS hour")
	}
	minute, err := strconv.Atoi(p.minute)
	if err != nil {
		return "", errors.New("invalid CUPS minute")
	}
	second, err := strconv.Atoi(p.second)
	if err != nil {
		return "", errors.New("invalid CUPS second")
	}
	if p.meridiem != "" {
		if hour < 1 || hour > 12 {
			return "", errors.New("invalid CUPS hour")
		}
		if p.meridiem == "PM" && hour < 12 {
			hour += 12
		}
		if p.meridiem == "AM" && hour == 12 {
			hour = 0
		}
	} else if hour > 23 {
		return "", errors.New("invalid CUPS hour")
	}
	if minute > 59 || second > 59 {
		return "", errors.New("invalid CUPS time")
	}
	zone := time.UTC
	if p.zone != "" && p.zone != "UTC" {
		sign := 1
		if p.zone[0] == '-' {
			sign = -1
		}
		digits := strings.ReplaceAll(p.zone[1:], ":", "")
		zh, _ := strconv.Atoi(digits[:2])
		zm, _ := strconv.Atoi(digits[2:])
		if zh > 23 || zm > 59 {
			return "", errors.New("invalid CUPS zone")
		}
		zone = time.FixedZone("cups", sign*(zh*60+zm)*60)
	}
	value := time.Date(year, month, day, hour, minute, second, 0, zone)
	if value.Year() != year || value.Month() != month || value.Day() != day {
		return "", errors.New("invalid CUPS date")
	}
	if value.Weekday().String()[:3] != p.weekday {
		return "", errors.New("CUPS weekday mismatch")
	}
	return value.UTC().Format("2006-01-02T15:04:05Z"), nil
}

func (s Statistics) Validate() error {
	if s.Version != StatisticsVersion || s.Type != StatisticsType || s.Source != StatisticsSource || s.ObservedAt == "" || len(s.Jobs) > StatisticsMaxJobs {
		return errors.New("invalid printer statistics")
	}
	if _, err := time.Parse(time.RFC3339Nano, s.ObservedAt); err != nil {
		return errors.New("invalid printer statistics timestamp")
	}
	if s.ErrorCategory != nil {
		switch *s.ErrorCategory {
		case StatisticsErrorBinaryMissing, StatisticsErrorTimeout, StatisticsErrorContextCanceled, StatisticsErrorOutputLimit, StatisticsErrorCommandFailed, StatisticsErrorMalformed, StatisticsErrorJobLimit:
		default:
			return errors.New("invalid printer statistics error")
		}
	}
	seen := make(map[string]struct{}, len(s.Jobs))
	for _, job := range s.Jobs {
		if !safeStatisticsQueueName(job.QueueName) || len(job.JobKey) != 64 || strings.Trim(job.JobKey, "0123456789abcdef") != "" || job.CUPSJobID == 0 || job.CUPSJobID > StatisticsMaxJobID || job.SizeBytes > StatisticsMaxSizeBytes {
			return errors.New("invalid printer statistics job")
		}
		if _, err := time.Parse("2006-01-02T15:04:05Z", job.CompletedAt); err != nil {
			return errors.New("invalid printer statistics completion timestamp")
		}
		if _, ok := seen[job.JobKey]; ok {
			return errors.New("duplicate printer statistics job")
		}
		seen[job.JobKey] = struct{}{}
	}
	if s.Truncated && s.ErrorCategory == nil {
		return errors.New("truncated statistics requires an error")
	}
	return nil
}

func StatisticsCanonicalPayload(s Statistics) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	jobs := append([]StatisticsJob(nil), s.Jobs...)
	sort.Slice(jobs, func(i, j int) bool { return canonicalJobLess(jobs[i], jobs[j]) })
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	lines := []string{
		"printer-statistics-canonical-v1",
		"version=" + encode("1"),
		"type=" + encode(s.Type),
		"source=" + encode(s.Source),
		"observedAt=" + encode(s.ObservedAt),
		"errorCategory=" + encode(func() string {
			if s.ErrorCategory == nil {
				return ""
			}
			return string(*s.ErrorCategory)
		}()),
		"truncated=" + encode(strconv.FormatBool(s.Truncated)),
		"jobCount=" + encode(strconv.Itoa(len(jobs))),
	}
	for _, job := range jobs {
		lines = append(lines, "job="+encode(job.QueueName)+"\t"+encode(job.JobKey)+"\t"+strconv.FormatUint(job.CUPSJobID, 10)+"\t"+strconv.FormatUint(job.SizeBytes, 10)+"\t"+encode(job.CompletedAt))
	}
	data := []byte(strings.Join(lines, "\n") + "\n")
	if len(data) > StatisticsMaxMessageBytes {
		return nil, errors.New("printer statistics canonical payload is too large")
	}
	return data, nil
}

func StatisticsHash(s Statistics) (string, error) {
	data, err := StatisticsCanonicalPayload(s)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (s Statistics) MarshalBounded() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if err != nil || len(data) > StatisticsMaxMessageBytes {
		return nil, errors.New("printer statistics message is too large")
	}
	return data, nil
}
