package printer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCollectFitsCompleteOptionRecordsAndQueueEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		queues, options, choices int
		rich                     bool
	}{
		{"option-heavy", 3, 20, 32, false}, {"canonical-only", 1, 20, 65, false}, {"rich-queues", MaxQueues, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output strings.Builder
			for i := range tc.options {
				fmt.Fprintf(&output, "Option%d/Label:", i)
				for j := range tc.choices {
					if j == 0 {
						output.WriteString(" *Choice00")
					} else {
						fmt.Fprintf(&output, " Choice%02d", j)
					}
				}
				output.WriteByte('\n')
			}
			ppdDir := t.TempDir()
			names := make([]string, tc.queues)
			var transports strings.Builder
			for i := range tc.queues {
				names[i] = fmt.Sprintf("q%02d", i)
				if tc.rich {
					names[i] += strings.Repeat("x", MaxQueueNameBytes-len(names[i]))
				}
				uri := "ipp://printer/queue"
				if i == tc.queues-1 {
					uri = "usb://Other/model"
				}
				fmt.Fprintf(&transports, "device for %s: %s\n", names[i], uri)
				if tc.rich {
					if err := os.WriteFile(filepath.Join(ppdDir, names[i]+".ppd"), []byte("*CustomPageSize True\n*DefaultPageSize: Custom.90x70mm\n*ParamCustomPageSize Width: 1 points 36 576\n*ParamCustomPageSize Height: 2 points 36 3600\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			runner := RunnerFunc(func(_ context.Context, path string, args, env []string) ([]byte, []byte, error) {
				if path == "/options" {
					return []byte(output.String()), nil, nil
				}
				switch strings.Join(args, " ") {
				case "-r":
					return []byte("scheduler is running\n"), nil, nil
				case "-e":
					return []byte(strings.Join(names, "\n") + "\n"), nil, nil
				case "-v":
					return []byte(transports.String()), nil, nil
				}
				if args[0] == "-l" {
					extra := ""
					if tc.rich {
						extra = "printer-state-reasons: media-empty,cover-open,toner-low,marker-supply-low,door-open,media-jam\n"
					}
					return []byte("printer " + args[2] + " is idle.\n" + extra), nil, nil
				}
				if args[0] == "-a" {
					return []byte(args[1] + " accepting requests\n"), nil, nil
				}
				return nil, nil, nil
			})
			probe := NewProbe(Config{Runner: runner, OptionsPath: "/options", PPDDir: ppdDir, MaxStdoutBytes: 32 * 1024, Clock: func() time.Time { return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC) }})
			report, err := probe.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CanonicalPayloadHash(report); err != nil {
				data, _ := json.Marshal(report)
				t.Fatalf("report cannot be signed: bytes=%d: %v", len(data), err)
			}
			again, err := probe.Collect(context.Background())
			if err != nil || !reflect.DeepEqual(report, again) {
				t.Fatal("collection is not deterministic")
			}
			original := ParseQueueOptions([]byte(output.String()))
			remaining := 0
			clipped := false
			usbFound := false
			for i, q := range report.Queues {
				if i > 0 && report.Queues[i-1].Name >= q.Name {
					t.Fatal("queues not canonical sorted")
				}
				if q.DeviceTransport == DeviceTransportUSB {
					usbFound = true
				}
				if q.QueueState != QueueIdle || q.AcceptingJobs != AcceptingYes {
					t.Fatal("required queue evidence lost")
				}
				if q.ErrorCategory != nil && *q.ErrorCategory == ErrorOutputLimit {
					clipped = true
				}
				for _, o := range q.Options {
					found := false
					for _, want := range original {
						if reflect.DeepEqual(o, want) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("partial option: %+v", o)
					}
					remaining++
				}
				if tc.rich && q.CustomMedia == nil {
					t.Fatal("supported custom media lost")
				}
			}
			if !usbFound {
				t.Fatal("USB priority queue dropped")
			}
			if tc.rich {
				if len(report.Queues) >= tc.queues || report.ErrorCategory == nil || *report.ErrorCategory != ErrorEnumerationLimit {
					t.Fatal("missing enumeration clipping evidence")
				}
			} else if remaining == 0 || remaining >= tc.queues*len(original) || !clipped || len(report.Queues) != tc.queues {
				t.Fatalf("incorrect option clipping: %d options, %d queues", remaining, len(report.Queues))
			}
		})
	}
}

func TestReadQueuePPDBoundsOmitsUnsupportedCapabilities(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name     string
		maxWidth int
		want     bool
	}{{"zebra", 576, true}, {"generic", 2000, false}} {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf("*CustomPageSize True\n*ParamCustomPageSize Width: 1 points 36 %d\n*ParamCustomPageSize Height: 2 points 36 3600\n", tc.maxWidth)
			if err := os.WriteFile(filepath.Join(dir, tc.name+".ppd"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, ok := readQueuePPDBounds(dir, tc.name); ok != tc.want {
				t.Fatalf("advertised=%v want %v", ok, tc.want)
			}
		})
	}
}

func TestReportFittingPreservesErrorsAndRejectsInvalidEvidence(t *testing.T) {
	report := Report{Version: Version, Type: Type, Source: Source, ObservedAt: "2026-09-10T12:00:00Z", Scheduler: SchedulerRunning, Transport: TransportReachable, Queues: []QueueReport{{Name: "q", QueueState: QueueIdle, AcceptingJobs: AcceptingYes, PhysicalState: PhysicalUnknown, SampledAt: "2026-09-10T12:00:00Z", ErrorCategory: categoryPtr(ErrorTimeout)}}}
	for i := range 20 {
		choices := make([]string, 65)
		for j := range choices {
			choices[j] = fmt.Sprintf("Choice%02d", j)
		}
		report.Queues[0].Options = append(report.Queues[0].Options, QueueOption{Name: fmt.Sprintf("Option%d", i), Choices: choices})
	}
	fitted, err := fitCollectedReport(report)
	if err != nil || fitted.Queues[0].ErrorCategory == nil || *fitted.Queues[0].ErrorCategory != ErrorTimeout || len(fitted.Queues[0].Options) >= 20 {
		t.Fatalf("prior error lost: %v %+v", err, fitted)
	}
	report.Queues[0].Name = "../invalid"
	if _, err := fitCollectedReport(report); err == nil || errors.Is(err, errReportSize) {
		t.Fatalf("invalid evidence masked: %v", err)
	}
}
