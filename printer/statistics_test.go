package printer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStatisticsProbeUsesFixedSuccessfulLPStatAndRedactsOutput(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		"-W successful -o": {stdout: "zebra-42 alice 1234 Wed Aug 26 12:30:00 2026\nzebra-41 bob 500 Thu Aug 27 01:00:00 2026\n"},
	}}
	probe := NewStatisticsProbe(StatisticsConfig{Runner: runner, Clock: func() time.Time { return fixedClock() }, Path: "/test/lpstat"})
	stats, err := probe.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.ErrorCategory != nil || stats.Truncated || len(stats.Jobs) != 2 {
		t.Fatalf("stats = %#v", stats)
	}
	if stats.Jobs[0].CUPSJobID != 41 || stats.Jobs[1].CUPSJobID != 42 {
		t.Fatalf("jobs not deterministically sorted: %#v", stats.Jobs)
	}
	data, _ := json.Marshal(stats)
	if strings.Contains(string(data), "alice") || strings.Contains(string(data), "Wed Aug") {
		t.Fatal("raw user/date leaked")
	}
	if !reflect.DeepEqual(runner.argv, [][]string{{"-W", "successful", "-o"}}) {
		t.Fatalf("argv = %#v", runner.argv)
	}
	if !reflect.DeepEqual(runner.envs[0], []string{"LC_ALL=C", "LANG=C", "TZ=UTC"}) {
		t.Fatalf("env = %#v", runner.envs[0])
	}
}

func TestStatisticsProbeEncodesNoJobsAsArray(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{"-W successful -o": {}}}
	probe := NewStatisticsProbe(StatisticsConfig{Runner: runner, Clock: func() time.Time { return fixedClock() }, Path: "/test/lpstat"})
	stats, err := probe.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := stats.MarshalBounded()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Jobs == nil || !strings.Contains(string(data), `"jobs":[]`) {
		t.Fatalf("zero jobs did not encode as an array: %s", data)
	}
}

func TestStatisticsParserRejectsMalformedAndSelectsNewestBoundedJobs(t *testing.T) {
	if jobs, category, truncated := ParseStatisticsOutput([]byte("zebra-1 alice nope Wed Aug 26")); len(jobs) != 0 || category != StatisticsErrorMalformed || truncated {
		t.Fatalf("malformed = %v %#v %v", category, jobs, truncated)
	}
	var lines strings.Builder
	for index := 1; index <= StatisticsMaxJobs+1; index++ {
		lines.WriteString("zebra-")
		lines.WriteString(strconv.Itoa(index))
		lines.WriteString(" user 10 Wed Aug 26 12:00:00 2026\n")
	}
	jobs, category, truncated := ParseStatisticsOutput([]byte(lines.String()))
	if category != StatisticsErrorJobLimit || !truncated || len(jobs) != StatisticsMaxJobs {
		t.Fatalf("bounded = %v %v %d", category, truncated, len(jobs))
	}
	if jobs[0].CUPSJobID != 2 || jobs[len(jobs)-1].CUPSJobID != StatisticsMaxJobs+1 {
		t.Fatalf("oldest/newest selection = %d..%d", jobs[0].CUPSJobID, jobs[len(jobs)-1].CUPSJobID)
	}
}

func TestParseCompletionTimestampSupportsSingleDigitDayAndUTCOffset(t *testing.T) {
	if got, err := parseCUPSTimestamp("Sun Aug 9 12:30:00 2026"); err != nil || got != "2026-08-09T12:30:00Z" {
		t.Fatalf("single-digit day = %q, %v", got, err)
	}
	if got, err := parseCUPSTimestamp("Wed Aug 26 02:30:00 -0400 2026"); err != nil || got != "2026-08-26T06:30:00Z" {
		t.Fatalf("offset form = %q, %v", got, err)
	}
	if _, err := parseCUPSTimestamp("Wed Aug 26 12:30:00 2026 trailing"); err == nil {
		t.Fatal("malformed completion timestamp was accepted")
	}
}

func TestCUPSTimestampsShareStrictDateValidation(t *testing.T) {
	for _, value := range []string{
		"Thu Aug 27 13:02:03 2026", "Thu Aug 27 1:02:03 PM 2026",
		"Thu 27 Aug 2026 13:02:03", "Thu 27 Aug 2026 1:02:03 PM",
	} {
		if got, err := parseCUPSTimestamp(value); err != nil || got != "2026-08-27T13:02:03Z" {
			t.Errorf("timestamp %q: %q, %v", value, got, err)
		}
	}
	for _, value := range []string{
		"Fri Aug 27 13:02:03 2026", "Thu Aug 27 13:02:03 PM 2026",
		"Thu 31 Feb 2026 13:02:03", "Thu 27 Aug 2026 25:02:03",
		"Thu 27 Aug 2026 13:02:03 +2500", "Thu 27 Aug 2026 13:02:03 trailing",
	} {
		if _, err := parseCUPSTimestamp(value); err == nil {
			t.Errorf("invalid timestamp accepted: %q", value)
		}
	}
}

func TestStatisticsParserSelectsNewestIDsAcrossQueuesBeforeCanonicalSort(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "printer-statistics-truncation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Queues []struct {
			QueueName  string `json:"queueName"`
			FirstJobID int    `json:"firstJobId"`
			Count      int    `json:"count"`
		} `json:"queues"`
		MaxJobs        int            `json:"maxJobs"`
		ExpectedCounts map[string]int `json:"expectedCounts"`
		ExpectedFirst  []any          `json:"expectedFirst"`
		ExpectedLast   []any          `json:"expectedLast"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var lines strings.Builder
	for _, queue := range fixture.Queues {
		for index := 0; index < queue.Count; index++ {
			lines.WriteString(queue.QueueName)
			lines.WriteString("-")
			lines.WriteString(strconv.Itoa(queue.FirstJobID + index))
			lines.WriteString(" user 10 Wed Aug 26 12:00:00 2026\n")
		}
	}
	jobs, category, truncated := ParseStatisticsOutput([]byte(lines.String()))
	if category != StatisticsErrorJobLimit || !truncated || len(jobs) != fixture.MaxJobs {
		t.Fatalf("mixed bounded = %v %v %d", category, truncated, len(jobs))
	}
	counts := map[string]int{}
	for _, job := range jobs {
		counts[job.QueueName]++
	}
	for queue, expected := range fixture.ExpectedCounts {
		if counts[queue] != expected {
			t.Fatalf("global newest selection retained %s=%d, want %d", queue, counts[queue], expected)
		}
	}
	if jobs[0].QueueName != fixture.ExpectedFirst[0] || int(jobs[0].CUPSJobID) != int(fixture.ExpectedFirst[1].(float64)) || jobs[len(jobs)-1].QueueName != fixture.ExpectedLast[0] || int(jobs[len(jobs)-1].CUPSJobID) != int(fixture.ExpectedLast[1].(float64)) {
		t.Fatalf("canonical retained ordering = %#v ... %#v", jobs[0], jobs[len(jobs)-1])
	}
}

func TestStatisticsParserTrimsLongQueueJobsUntilEveryEncodingFits(t *testing.T) {
	var lines strings.Builder
	for index := 1; index <= StatisticsMaxJobs; index++ {
		queue := strings.Repeat("q", 123) + strconv.Itoa(index)
		lines.WriteString(queue)
		lines.WriteString("-1 user 10 Wed Aug 26 12:00:00 2026\n")
	}
	jobs, category, truncated := ParseStatisticsOutput([]byte(lines.String()))
	if category != StatisticsErrorJobLimit || !truncated || len(jobs) >= StatisticsMaxJobs {
		t.Fatalf("long queue bound = %v %v %d", category, truncated, len(jobs))
	}
	stats := Statistics{Version: StatisticsVersion, Type: StatisticsType, Source: StatisticsSource, ObservedAt: fixedClock().Format(time.RFC3339Nano), ErrorCategory: statisticsCategoryPtr(category), Truncated: truncated, Jobs: jobs}
	if _, err := StatisticsHash(stats); err != nil {
		t.Fatalf("trimmed statistics hash failed: %v", err)
	}
	if jobs[len(jobs)-1].QueueName <= jobs[0].QueueName {
		t.Fatalf("trimmed jobs lost canonical ordering: %#v", jobs)
	}
}

func TestStatisticsJobKeyMatchesFixture(t *testing.T) {
	key := StatisticsJobKey("zebra", 7, 10, "Wed Aug 26 12:00:00 2026")
	if key != "bcd87d1be599d120eec27d6b8bfd685ef8f9ed1e3df94786217bce884f83cc23" {
		t.Fatalf("job key changed: %s", key)
	}
}

func TestStatisticsHashMatchesSharedFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "printer-statistics-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Statistics
		ExpectedHash string `json:"expectedHash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	hash, err := StatisticsHash(fixture.Statistics)
	if err != nil {
		t.Fatal(err)
	}
	if hash != fixture.ExpectedHash {
		t.Fatalf("fixture hash = %s, want %s", hash, fixture.ExpectedHash)
	}
}

func TestStatisticsProbeClassifiesCommandFailure(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{"-W successful -o": {err: errors.New("lpstat failed with user data")}}}
	stats, err := NewStatisticsProbe(StatisticsConfig{Runner: runner, Clock: func() time.Time { return fixedClock() }}).Collect(context.Background())
	if err != nil || stats.ErrorCategory == nil || *stats.ErrorCategory != StatisticsErrorCommandFailed || stats.Truncated {
		t.Fatalf("failure = %#v err=%v", stats, err)
	}
}

func TestStatisticsProbeParseFailureKeepsEmptyJobArray(t *testing.T) {
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
		report, err := NewStatisticsProbe(StatisticsConfig{Runner: runner, Clock: fixedClock}).Collect(t.Context())
		if err != nil || report.ErrorCategory == nil || *report.ErrorCategory != StatisticsErrorMalformed || report.Truncated || len(report.Jobs) != 0 {
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
		if _, err := StatisticsHash(report); err != nil {
			t.Fatalf("diagnostic report cannot be signed: %v", err)
		}
	}
}
