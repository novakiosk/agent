package printer

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type jobsRunner struct {
	stdout []byte
	stderr []byte
	err    error
	path   string
	args   []string
	env    []string
}

func (r *jobsRunner) Run(_ context.Context, path string, args []string, env []string) ([]byte, []byte, error) {
	r.path, r.args, r.env = path, append([]string(nil), args...), append([]string(nil), env...)
	return r.stdout, r.stderr, r.err
}

func TestParseJobsOutputDiscardsPersonalFieldsAndCanonicalizesTimestamp(t *testing.T) {
	output := []byte("zebra-41 alice 1200 Thu 27 Aug 2026 01:02:03\nzebra-42 bob 20 Label Title Thu Aug 27 01:02:04 2026\nzebra-43 carol 10 Thu Aug 27 23:00:00 -0500 2026\n")
	jobs, category, truncated := ParseJobsOutput(output)
	if category != "" || truncated || len(jobs) != 3 {
		t.Fatalf("jobs=%+v category=%q truncated=%v", jobs, category, truncated)
	}
	if jobs[0].SubmittedAt != "2026-08-27T01:02:03Z" || jobs[1].SubmittedAt != "2026-08-27T01:02:04Z" || jobs[2].SubmittedAt != "2026-08-28T04:00:00Z" {
		t.Fatalf("timestamps=%+v", jobs)
	}
	if strings.Contains(string(mustJobsJSON(t, jobs)), "alice") || strings.Contains(string(mustJobsJSON(t, jobs)), "Label") {
		t.Fatal("personal/title text escaped into active job evidence")
	}
	if jobs[0].JobKey != JobsJobKey("zebra", 41, 1200, jobs[0].SubmittedAt) {
		t.Fatal("job key is not derived from canonical fields")
	}
}

func TestParseJobsOutputRejectsMalformedAndBounds(t *testing.T) {
	for _, output := range []string{
		"zebra-no-id alice 10 Thu 27 Aug 2026 01:02:03\n",
		"zebra-1 alice nope Thu 27 Aug 2026 01:02:03\n",
		"zebra-1 alice 10 Thu 27 Foo 2026 01:02:03\n",
		"zebra-1 alice 10 Thu 27 Aug 2026 25:02:03\n",
		"zebra-1 alice 10 Thu 27 Aug 2026 01:02:03 trailing\n",
	} {
		jobs, category, truncated := ParseJobsOutput([]byte(output))
		if jobs == nil || len(jobs) != 0 || category != JobsErrorMalformed || truncated {
			t.Fatalf("output %q yielded jobs=%+v category=%q truncated=%v", output, jobs, category, truncated)
		}
	}
	jobs, category, truncated := ParseJobsOutput(make([]byte, JobsMaxOutputBytes+1))
	if jobs == nil || len(jobs) != 0 || category != JobsErrorOutputLimit || !truncated {
		t.Fatalf("oversize output yielded jobs=%+v category=%q truncated=%v", jobs, category, truncated)
	}
}

func TestJobsProbeUsesFixedLocaleAndReportsFailuresWithoutRawOutput(t *testing.T) {
	runner := &jobsRunner{stdout: []byte("zebra-1 owner 10 Thu 27 Aug 2026 01:02:03\n"), stderr: []byte("secret title"), err: nil}
	probe := NewJobsProbe(JobsConfig{Runner: runner, Clock: func() time.Time { return time.Date(2026, 8, 27, 1, 3, 0, 0, time.UTC) }})
	report, err := probe.Collect(context.Background())
	if err != nil || report.ErrorCategory != nil || len(report.Jobs) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if runner.path != "/usr/bin/lpstat" || !reflect.DeepEqual(runner.args, []string{"-W", "not-completed", "-o"}) || !reflect.DeepEqual(runner.env, []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}) {
		t.Fatalf("unsafe probe invocation path=%q args=%v env=%v", runner.path, runner.args, runner.env)
	}
	runner.err = errors.New("fixed command failed")
	runner.stdout = []byte("partial secret output")
	report, err = probe.Collect(context.Background())
	if err != nil || report.ErrorCategory == nil || *report.ErrorCategory != JobsErrorCommandFailed || len(report.Jobs) != 0 || strings.Contains(string(mustJobsJSON(t, report)), "secret") {
		t.Fatalf("failure report=%+v err=%v", report, err)
	}
}

func TestJobsProbeCapturesExecOutput(t *testing.T) {
	// echo is deliberately not an lpstat fixture: its fixed invocation emits
	// malformed evidence. The probe must capture that output and fail closed;
	// an accidentally unwired Stdout would look like a valid empty queue.
	probe := NewJobsProbe(JobsConfig{Path: "/bin/echo", Clock: func() time.Time { return time.Date(2026, 8, 27, 1, 3, 0, 0, time.UTC) }})
	report, err := probe.Collect(context.Background())
	if err != nil || report.ErrorCategory == nil || *report.ErrorCategory != JobsErrorMalformed {
		t.Fatalf("exec output was not captured: report=%+v err=%v", report, err)
	}
}

func TestJobsCanonicalHashAndValidation(t *testing.T) {
	jobs, category, truncated := ParseJobsOutput([]byte("zebra-1 owner 10 Thu 27 Aug 2026 01:02:03\n"))
	if category != "" || truncated {
		t.Fatal("valid output was rejected")
	}
	report := Jobs{Version: JobsVersion, Type: JobsType, Source: JobsSource, ObservedAt: "2026-08-27T01:03:00Z", Jobs: jobs}
	hash, err := JobsHash(report)
	if err != nil || len(hash) != 64 || report.Validate() != nil {
		t.Fatalf("report hash/validation failed hash=%q err=%v validate=%v", hash, err, report.Validate())
	}
	bad := report
	bad.Jobs = append([]ActiveJob(nil), report.Jobs...)
	bad.Jobs[0].JobKey = strings.Repeat("0", 64)
	if bad.Validate() == nil {
		t.Fatal("mismatched active job key accepted")
	}
}

func mustJobsJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestJobsProbeParseFailureKeepsEmptyJobArray(t *testing.T) {
	const valid = "queue-7 private-user 10 Wed Aug 26 12:30:00 2026\n"
	for _, output := range []string{
		"invalid record",
		"queue-0 private-user 10 Wed Aug 26 12:30:00 2026\n",
		"queue-7 private-user invalid Wed Aug 26 12:30:00 2026\n",
		"queue-7 private-user 10 invalid timestamp\n",
		valid + "invalid record",
	} {
		runner := RunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
			return []byte(output), nil, nil
		})
		report, err := NewJobsProbe(JobsConfig{Runner: runner, Clock: fixedClock}).Collect(t.Context())
		if err != nil || report.ErrorCategory == nil || *report.ErrorCategory != JobsErrorMalformed || report.Truncated || len(report.Jobs) != 0 {
			t.Fatalf("parse failure lost: %+v, %v", report, err)
		}
		encoded, err := report.MarshalBounded()
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		if string(wire["jobs"]) != "[]" {
			t.Fatalf("control plane requires an empty array, got %s", wire["jobs"])
		}
		if strings.Contains(string(encoded), "private-user") || strings.Contains(string(encoded), "invalid record") {
			t.Fatal("raw CUPS output entered report")
		}
		if _, err := JobsHash(report); err != nil {
			t.Fatalf("diagnostic report cannot be signed: %v", err)
		}
	}
}
