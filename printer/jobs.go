package printer

// This file is the deliberately separate active-job evidence stream.  The
// completed-job statistics collector must not be used for cancellation: CUPS
// active rows have a different lifecycle and are replaced on every complete
// sample.

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
	JobsVersion                  = 1
	JobsType                     = "printer.jobs"
	JobsSource                   = "local-cups-lpstat-active-v1"
	JobsMaxJobs                  = 128
	JobsMaxQueueNameBytes        = 127
	JobsMaxOutputBytes           = 64 * 1024
	JobsMaxMessageBytes          = 64 * 1024
	JobsMaxJobID          uint64 = 2_147_483_647
	JobsMaxSizeBytes      uint64 = 1 << 40
	JobsMaxUserBytes             = 128
	jobsCommandTimeout           = 5 * time.Second
)

type JobsErrorCategory string

const (
	JobsErrorBinaryMissing JobsErrorCategory = "binary_missing"
	JobsErrorTimeout       JobsErrorCategory = "timeout"
	JobsErrorContextCancel JobsErrorCategory = "context_canceled"
	JobsErrorOutputLimit   JobsErrorCategory = "output_limit"
	JobsErrorCommandFailed JobsErrorCategory = "command_failed"
	JobsErrorMalformed     JobsErrorCategory = "printer_jobs_output_invalid"
	JobsErrorJobLimit      JobsErrorCategory = "printer_jobs_job_limit"
)

type ActiveJob struct {
	QueueName   string `json:"queueName"`
	JobKey      string `json:"jobKey"`
	CUPSJobID   uint64 `json:"cupsJobId"`
	SizeBytes   uint64 `json:"sizeBytes"`
	SubmittedAt string `json:"submittedAt"`
}

type Jobs struct {
	Version       int                `json:"version"`
	Type          string             `json:"type"`
	Source        string             `json:"source"`
	ObservedAt    string             `json:"observedAt"`
	ErrorCategory *JobsErrorCategory `json:"errorCategory"`
	Truncated     bool               `json:"truncated"`
	Jobs          []ActiveJob        `json:"jobs"`
}

type JobsConfig struct {
	Runner         Runner
	Clock          func() time.Time
	Path           string
	CommandTimeout time.Duration
	MaxOutputBytes int
}

type JobsProbe struct {
	runner         Runner
	clock          func() time.Time
	path           string
	commandTimeout time.Duration
	maxOutputBytes int
}

func NewJobsProbe(config ...JobsConfig) *JobsProbe {
	c := JobsConfig{}
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
		timeout = jobsCommandTimeout
	}
	maxOutput := c.MaxOutputBytes
	if maxOutput <= 0 || maxOutput > JobsMaxOutputBytes {
		maxOutput = JobsMaxOutputBytes
	}
	return &JobsProbe{runner: c.Runner, clock: clock, path: path, commandTimeout: timeout, maxOutputBytes: maxOutput}
}

func (p *JobsProbe) Collect(ctx context.Context) (Jobs, error) {
	if p == nil || ctx == nil {
		return Jobs{}, errors.New("printer jobs: invalid probe context")
	}
	now := p.clock().UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := Jobs{Version: JobsVersion, Type: JobsType, Source: JobsSource, ObservedAt: now.Format(time.RFC3339Nano), Jobs: []ActiveJob{}}
	commandCtx, cancel := context.WithTimeout(ctx, p.commandTimeout)
	defer cancel()
	stdout, _, err, category := p.run(commandCtx)
	if err != nil {
		result.ErrorCategory = jobsCategoryPtr(category)
		result.Truncated = category == JobsErrorOutputLimit
		if category == JobsErrorContextCancel && ctx.Err() == nil {
			result.ErrorCategory = jobsCategoryPtr(JobsErrorTimeout)
			result.Truncated = true
		}
		return result, nil
	}
	parsed, parseCategory, truncated := ParseJobsOutput(stdout)
	result.Jobs = parsed
	result.ErrorCategory = jobsCategoryPtr(parseCategory)
	result.Truncated = truncated
	return result, nil
}

func (p *JobsProbe) run(ctx context.Context) ([]byte, []byte, error, JobsErrorCategory) {
	if p.runner != nil {
		stdout, stderr, err := p.runner.Run(ctx, p.path, []string{"-W", "not-completed", "-o"}, []string{"LC_ALL=C", "LANG=C", "TZ=UTC"})
		if len(stdout) > p.maxOutputBytes || len(stderr) > p.maxOutputBytes {
			return nil, nil, errOutputLimit, JobsErrorOutputLimit
		}
		if err == nil {
			return stdout, stderr, nil, ""
		}
		return stdout, stderr, err, classifyJobsError(err, ctx)
	}
	command := exec.CommandContext(ctx, p.path, "-W", "not-completed", "-o")
	command.Env = []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = p.maxOutputBytes, p.maxOutputBytes
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, nil, errOutputLimit, JobsErrorOutputLimit
	}
	if err == nil {
		return stdout.data.Bytes(), stderr.data.Bytes(), nil, ""
	}
	return stdout.data.Bytes(), stderr.data.Bytes(), err, classifyJobsError(err, ctx)
}

func classifyJobsError(err error, ctx context.Context) JobsErrorCategory {
	if errors.Is(err, errOutputLimit) {
		return JobsErrorOutputLimit
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return JobsErrorTimeout
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return JobsErrorContextCancel
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return JobsErrorBinaryMissing
	}
	return JobsErrorCommandFailed
}

func jobsCategoryPtr(category JobsErrorCategory) *JobsErrorCategory {
	if category == "" {
		return nil
	}
	c := category
	return &c
}

var activeJobToken = regexp.MustCompile(`^([A-Za-z0-9._-]+)-([0-9]+)$`)

// ParseJobsOutput accepts CUPS' fixed C-locale lpstat -o records.  The user,
// optional title, and any other display-only text are parsed solely to locate
// the trailing submitted timestamp; none of those values are retained.
func ParseJobsOutput(output []byte) ([]ActiveJob, JobsErrorCategory, bool) {
	if len(output) > JobsMaxOutputBytes {
		return []ActiveJob{}, JobsErrorOutputLimit, true
	}
	lines := bytes.Split(bytes.ReplaceAll(output, []byte("\r\n"), []byte("\n")), []byte("\n"))
	jobs := make([]ActiveJob, 0, min(len(lines), JobsMaxJobs))
	seen := make(map[string]struct{})
	for _, raw := range lines {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			return []ActiveJob{}, JobsErrorMalformed, false
		}
		match := activeJobToken.FindStringSubmatch(fields[0])
		if match == nil || !safeJobsQueueName(match[1]) {
			return []ActiveJob{}, JobsErrorMalformed, false
		}
		id, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil || id == 0 || id > JobsMaxJobID {
			return []ActiveJob{}, JobsErrorMalformed, false
		}
		if len(fields[1]) == 0 || len(fields[1]) > JobsMaxUserBytes || hasStatisticsControl(fields[1]) {
			return []ActiveJob{}, JobsErrorMalformed, false
		}
		size, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil || size > JobsMaxSizeBytes {
			return []ActiveJob{}, JobsErrorMalformed, false
		}
		submitted, err := parseSubmittedTimestamp(fields[3:])
		if err != nil {
			return []ActiveJob{}, JobsErrorMalformed, false
		}
		key := JobsJobKey(match[1], id, size, submitted)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		jobs = append(jobs, ActiveJob{QueueName: match[1], JobKey: key, CUPSJobID: id, SizeBytes: size, SubmittedAt: submitted})
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].QueueName != jobs[j].QueueName {
			return jobs[i].QueueName < jobs[j].QueueName
		}
		return jobs[i].CUPSJobID < jobs[j].CUPSJobID
	})
	if len(jobs) > JobsMaxJobs {
		jobs = jobs[len(jobs)-JobsMaxJobs:]
		return jobs, JobsErrorJobLimit, true
	}
	return jobs, "", false
}

func parseSubmittedTimestamp(fields []string) (string, error) {
	// An optional title may precede the final timestamp fields.
	for start := range fields {
		candidate := strings.Join(fields[start:], " ")
		if value, err := parseCUPSTimestamp(candidate); err == nil {
			return value, nil
		}
	}
	return "", errors.New("invalid active CUPS timestamp")
}

func safeJobsQueueName(value string) bool {
	return len(value) >= 1 && len(value) <= JobsMaxQueueNameBytes && statisticsQueueNamePattern.MatchString(value)
}

func JobsJobKey(queue string, id, size uint64, submittedAt string) string {
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	canonical := strings.Join([]string{"printer-jobs-job-key-v1", "queue=" + encode(queue), "cupsJobId=" + strconv.FormatUint(id, 10), "sizeBytes=" + strconv.FormatUint(size, 10), "submittedAt=" + encode(submittedAt), ""}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func (j Jobs) Validate() error {
	if j.Version != JobsVersion || j.Type != JobsType || j.Source != JobsSource || j.ObservedAt == "" || len(j.Jobs) > JobsMaxJobs {
		return errors.New("invalid printer jobs")
	}
	parsed, err := time.Parse(time.RFC3339Nano, j.ObservedAt)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != j.ObservedAt {
		return errors.New("invalid printer jobs timestamp")
	}
	if j.ErrorCategory != nil {
		switch *j.ErrorCategory {
		case JobsErrorBinaryMissing, JobsErrorTimeout, JobsErrorContextCancel, JobsErrorOutputLimit, JobsErrorCommandFailed, JobsErrorMalformed, JobsErrorJobLimit:
		default:
			return errors.New("invalid printer jobs error")
		}
	}
	seen := make(map[string]struct{}, len(j.Jobs))
	for _, job := range j.Jobs {
		if !safeJobsQueueName(job.QueueName) || len(job.JobKey) != 64 || strings.Trim(job.JobKey, "0123456789abcdef") != "" || job.CUPSJobID == 0 || job.CUPSJobID > JobsMaxJobID || job.SizeBytes > JobsMaxSizeBytes {
			return errors.New("invalid printer job")
		}
		submitted, err := time.Parse("2006-01-02T15:04:05Z", job.SubmittedAt)
		if err != nil || submitted.Location() != time.UTC || JobsJobKey(job.QueueName, job.CUPSJobID, job.SizeBytes, job.SubmittedAt) != job.JobKey {
			return errors.New("invalid printer job timestamp or key")
		}
		if _, duplicate := seen[job.JobKey]; duplicate {
			return errors.New("duplicate printer job")
		}
		seen[job.JobKey] = struct{}{}
	}
	if j.Truncated && j.ErrorCategory == nil {
		return errors.New("truncated printer jobs require an error")
	}
	return nil
}

func JobsCanonicalPayload(j Jobs) ([]byte, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	jobs := append([]ActiveJob(nil), j.Jobs...)
	sort.Slice(jobs, func(i, k int) bool {
		if jobs[i].QueueName != jobs[k].QueueName {
			return jobs[i].QueueName < jobs[k].QueueName
		}
		return jobs[i].CUPSJobID < jobs[k].CUPSJobID
	})
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	errorCategory := ""
	if j.ErrorCategory != nil {
		errorCategory = string(*j.ErrorCategory)
	}
	lines := []string{"printer-jobs-canonical-v1", "version=" + encode("1"), "type=" + encode(j.Type), "source=" + encode(j.Source), "observedAt=" + encode(j.ObservedAt), "errorCategory=" + encode(errorCategory), "truncated=" + encode(strconv.FormatBool(j.Truncated)), "jobCount=" + encode(strconv.Itoa(len(jobs)))}
	for _, job := range jobs {
		lines = append(lines, "job="+encode(job.QueueName)+"\t"+encode(job.JobKey)+"\t"+strconv.FormatUint(job.CUPSJobID, 10)+"\t"+strconv.FormatUint(job.SizeBytes, 10)+"\t"+encode(job.SubmittedAt))
	}
	data := []byte(strings.Join(lines, "\n") + "\n")
	if len(data) > JobsMaxMessageBytes {
		return nil, errors.New("printer jobs canonical payload is too large")
	}
	return data, nil
}

func JobsHash(j Jobs) (string, error) {
	data, err := JobsCanonicalPayload(j)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (j Jobs) MarshalBounded() ([]byte, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(j)
	if err != nil || len(data) > JobsMaxMessageBytes {
		return nil, errors.New("printer jobs message is too large")
	}
	return data, nil
}
