package cupsjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

type fakeRunner struct {
	usbURI            string
	active            bool
	enabled           bool
	jobs              map[uint64]struct{}
	addJobOnCancelAll uint64
	args              [][]string
	err               error
	cancelErr         error
}

func (runner *fakeRunner) Run(_ context.Context, path string, args []string, _ []string) ([]byte, []byte, error) {
	runner.args = append(runner.args, append([]string{path}, args...))
	if runner.err != nil {
		return nil, nil, runner.err
	}
	switch path {
	case "/usr/bin/lpstat":
		if len(args) >= 2 && args[0] == "-v" {
			return []byte("device for " + args[1] + ": " + runner.usbURI + "\n"), nil, nil
		}
		if len(args) >= 2 && args[0] == "-p" {
			if runner.enabled {
				return []byte("printer " + args[1] + " is idle. enabled since Tue Aug 27 01:00:00 2026\n"), nil, nil
			}
			return []byte("printer " + args[1] + " disabled since Tue Aug 27 01:00:00 2026 -\n\tPaused from NOVA Kiosk\n"), nil, nil
		}
		if runner.jobs != nil {
			var output string
			for id := range runner.jobs {
				output += fmt.Sprintf("queue-%d user 30 Tue Aug 27 01:00:00 2026\n", id)
			}
			return []byte(output), nil, nil
		}
		if runner.active {
			return []byte("queue-7 user 30 Tue Aug 27 01:00:00 2026\n"), nil, nil
		}
		return nil, nil, nil
	case "/usr/bin/cancel":
		if len(args) == 2 && args[0] == "-a" {
			runner.jobs = map[uint64]struct{}{}
			if runner.addJobOnCancelAll != 0 {
				runner.jobs[runner.addJobOnCancelAll] = struct{}{}
			}
			if runner.cancelErr != nil {
				return nil, nil, runner.cancelErr
			}
			return nil, nil, nil
		}
		runner.active = false
		if runner.cancelErr != nil {
			return nil, nil, runner.cancelErr
		}
		return nil, nil, nil
	case "/usr/sbin/cupsdisable":
		runner.enabled = false
		return nil, nil, nil
	case "/usr/sbin/cupsenable":
		runner.enabled = true
		return nil, nil, nil
	default:
		return nil, nil, errors.New("unexpected executable")
	}
}

func validRequest() Request {
	return Request{Version: Version, Type: RequestType, Profile: "kiosk", Action: ActionCancel, CommandHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", QueueName: "queue", CUPSJobID: 7}
}

func TestCommandTimeoutAndPermissionCausesSurviveProbes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, _, err := (ExecRunner{}).Run(ctx, "/bin/sleep", []string{"10"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || classifyHelperError(err) != ErrorTimeout {
		t.Fatalf("command deadline lost: %v", err)
	}
	for _, cause := range []error{context.DeadlineExceeded, os.ErrPermission} {
		runner := &fakeRunner{err: cause}
		_, stateErr := queueEnabled(t.Context(), runner, "queue")
		_, jobsErr := activeQueueJobIDs(t.Context(), runner, "queue")
		if !errors.Is(stateErr, cause) || !errors.Is(jobsErr, cause) {
			t.Fatalf("probe lost %v: state=%v jobs=%v", cause, stateErr, jobsErr)
		}
	}
}

func validQueueRequest(action string) Request {
	return Request{Version: Version, Type: QueueRequestType, Profile: "kiosk", Action: action, CommandHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", QueueName: "queue"}
}

func TestRunCancelAcceptsExactUSBAndUsesFixedArgv(t *testing.T) {
	dir := t.TempDir()
	manifestDir := filepath.Join(dir, "manifest")
	if err := os.Mkdir(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{usbURI: "usb://Zebra/serial", active: true}
	request := validRequest()
	result := runCancel(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: manifestDir, Timeout: time.Second}, runner, request)
	if result.Result != ResultApplied || result.Error != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(runner.args) != 4 || runner.args[0][0] != "/usr/bin/lpstat" || runner.args[0][1] != "-v" || runner.args[0][2] != "queue" || runner.args[1][0] != "/usr/bin/lpstat" || runner.args[1][1] != "-W" || runner.args[1][2] != "not-completed" || runner.args[1][3] != "-o" || runner.args[1][4] != "queue" || runner.args[2][0] != "/usr/bin/cancel" || runner.args[2][1] != "queue-7" || runner.args[3][0] != "/usr/bin/lpstat" {
		t.Fatalf("unexpected fixed argv: %#v", runner.args)
	}
}

func TestRunCancelRejectsNetworkImplicitAndUnknownUSB(t *testing.T) {
	for _, uri := range []string{"ipp://10.0.0.2/printer", "implicitclass://proxy", "", "usb://Zebra/serial ", "usb://Zebra/serial\nextra"} {
		runner := &fakeRunner{usbURI: uri, active: true}
		result := runCancel(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, validRequest())
		if result.Result != ResultFailed || result.Error != ErrorQueueNotAllowed {
			t.Fatalf("uri %q: %#v", uri, result)
		}
		if len(runner.args) != 1 {
			t.Fatalf("uri %q ran unexpected commands: %#v", uri, runner.args)
		}
	}
}

func TestRunCancelRequiresAppliedManifestQueueNotClaim(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "print-bridge.json")
	write := func(value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifest, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{active: true}
	write(map[string]any{"version": 2, "queues": []string{}, "claims": []string{"queue"}, "settings": map[string][]string{}})
	result := runCancel(context.Background(), HelperConfig{Profile: "print-bridge", ManifestDir: dir, Timeout: time.Second}, runner, func() Request { request := validRequest(); request.Profile = "print-bridge"; return request }())
	if result.Error != ErrorQueueNotAllowed || len(runner.args) != 0 {
		t.Fatalf("claim unexpectedly authorized: %#v %#v", result, runner.args)
	}
	write(map[string]any{"version": 2, "queues": []string{"queue"}, "settings": map[string][]string{"queue": {"PageSize"}}, "defaults": map[string]map[string]string{"queue": {"PageSize": "A4"}}})
	runner.active = true
	runner.args = nil
	result = runCancel(context.Background(), HelperConfig{Profile: "print-bridge", ManifestDir: dir, Timeout: time.Second}, runner, func() Request { request := validRequest(); request.Profile = "print-bridge"; return request }())
	if result.Result != ResultApplied {
		t.Fatalf("applied manifest was rejected: %#v", result)
	}
}

func TestRunCancelRejectsReservedNvsprint1EvenWhenManifestClaimsIt(t *testing.T) {
	dir := t.TempDir()
	data, err := json.Marshal(map[string]any{"version": 2, "queues": []string{"nvsprint1"}, "settings": map[string][]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "print-bridge.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.Profile = "print-bridge"
	request.QueueName = "nvsprint1"
	runner := &fakeRunner{active: true}
	result := runCancel(context.Background(), HelperConfig{Profile: request.Profile, ManifestDir: dir, Timeout: time.Second}, runner, request)
	if result.Result != ResultFailed || result.Error != ErrorQueueNotAllowed || len(runner.args) != 0 {
		t.Fatalf("reserved queue unexpectedly authorized: %#v %#v", result, runner.args)
	}
}

func TestRunCancelReportsRaceWithoutFalseApplied(t *testing.T) {
	runner := &fakeRunner{usbURI: "usb://Zebra/serial", active: false}
	result := runCancel(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, validRequest())
	if result.Result != ResultFailed || result.Error != ErrorNotActive {
		t.Fatalf("unexpected race result: %#v", result)
	}
}

func TestRunCancelPostchecksAfterCancelFailureAndReportsRace(t *testing.T) {
	runner := &fakeRunner{usbURI: "usb://Zebra/serial", active: true, cancelErr: errors.New("cancel failed")}
	result := runCancel(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, validRequest())
	if result.Result != ResultFailed || result.Error != ErrorNotActive {
		t.Fatalf("cancel race was not reported as not-active: %#v", result)
	}
	if len(runner.args) != 4 || runner.args[0][0] != "/usr/bin/lpstat" || runner.args[0][1] != "-v" || runner.args[2][0] != "/usr/bin/cancel" || runner.args[2][1] != "queue-7" || runner.args[3][0] != "/usr/bin/lpstat" || runner.args[3][1] != "-W" {
		t.Fatalf("unexpected fixed cancel/postcheck argv: %#v", runner.args)
	}
	for _, args := range runner.args {
		if args[0] == "/usr/bin/cancel" && args[1] != "queue-7" {
			t.Fatalf("cancel target was not derived exactly: %#v", runner.args)
		}
	}
}

func TestRunQueuePauseAndResumeUseFixedCommandsAndAreIdempotent(t *testing.T) {
	runner := &fakeRunner{usbURI: "usb://Zebra/serial", enabled: true}
	pause := validQueueRequest(ActionPause)
	result := runQueueAction(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, pause)
	if result.Result != ResultApplied || result.Error != "" || runner.enabled {
		t.Fatalf("pause result: %#v enabled=%v", result, runner.enabled)
	}
	if len(runner.args) != 4 || runner.args[1][0] != "/usr/bin/lpstat" || runner.args[1][1] != "-p" || runner.args[2][0] != "/usr/sbin/cupsdisable" || !reflect.DeepEqual(runner.args[2][1:], []string{"-r", "Paused from NOVA Kiosk", "queue"}) || runner.args[3][0] != "/usr/bin/lpstat" {
		t.Fatalf("pause argv: %#v", runner.args)
	}
	runner.args = nil
	result = runQueueAction(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, pause)
	if result.Result != ResultApplied || len(runner.args) != 2 {
		t.Fatalf("idempotent pause: %#v %#v", result, runner.args)
	}
	runner.args = nil
	resume := validQueueRequest(ActionResume)
	result = runQueueAction(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, resume)
	if result.Result != ResultApplied || !runner.enabled || len(runner.args) != 4 || runner.args[2][0] != "/usr/sbin/cupsenable" || !reflect.DeepEqual(runner.args[2][1:], []string{"queue"}) {
		t.Fatalf("resume result/argv: %#v %#v", result, runner.args)
	}
}

func TestRunQueueCancelAllVerifiesInitialJobsAndIgnoresNewJobs(t *testing.T) {
	runner := &fakeRunner{usbURI: "usb://Zebra/serial", jobs: map[uint64]struct{}{7: {}, 9: {}}, addJobOnCancelAll: 11}
	result := runQueueAction(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir(), Timeout: time.Second}, runner, validQueueRequest(ActionCancelAll))
	if result.Result != ResultApplied || result.Error != "" || result.AffectedJobs == nil || *result.AffectedJobs != 2 {
		t.Fatalf("cancel-all result: %#v", result)
	}
	if len(runner.args) != 4 || runner.args[1][0] != "/usr/bin/lpstat" || runner.args[2][0] != "/usr/bin/cancel" || !reflect.DeepEqual(runner.args[2][1:], []string{"-a", "queue"}) || runner.args[3][0] != "/usr/bin/lpstat" {
		t.Fatalf("cancel-all argv: %#v", runner.args)
	}
}

func TestRunQueueActionRetainsQueueAuthorityChecks(t *testing.T) {
	runner := &fakeRunner{usbURI: "ipp://10.0.0.2/printers/queue", enabled: true}
	result := runQueueAction(context.Background(), HelperConfig{Profile: "kiosk", ManifestDir: t.TempDir()}, runner, validQueueRequest(ActionPause))
	if result.Result != ResultFailed || result.Error != ErrorQueueNotAllowed || len(runner.args) != 1 {
		t.Fatalf("network queue unexpectedly authorized: %#v %#v", result, runner.args)
	}
}

func TestWriteResultUsesAgentStateOwnerAndRejectsDirectorySymlink(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, ResultFileName)
	if err := writeResult(path, Result{Version: Version, Type: ResultType, Profile: "kiosk", Action: ActionCancel, CommandHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", QueueName: "queue", CUPSJobID: 7, Result: ResultApplied}); err != nil {
		t.Fatalf("write result: %v (dir mode %o)", err, mustMode(stateDir))
	}
	resultInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if resultInfo.Mode().Perm() != 0o600 {
		t.Fatalf("result mode = %o, want 0600", resultInfo.Mode().Perm())
	}
	directoryInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	resultStat, resultOK := resultInfo.Sys().(*syscall.Stat_t)
	directoryStat, directoryOK := directoryInfo.Sys().(*syscall.Stat_t)
	if resultOK && directoryOK && (resultStat.Uid != directoryStat.Uid || resultStat.Gid != directoryStat.Gid) {
		t.Fatalf("result owner = %d:%d, state owner = %d:%d", resultStat.Uid, resultStat.Gid, directoryStat.Uid, directoryStat.Gid)
	}
	linkParent := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(stateDir, linkParent); err != nil {
		t.Fatal(err)
	}
	if err := writeResult(filepath.Join(linkParent, ResultFileName), Result{Version: Version, Type: ResultType, Profile: "kiosk", Action: ActionCancel, CommandHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", QueueName: "queue", CUPSJobID: 7, Result: ResultApplied}); err == nil {
		t.Fatal("result writer accepted a symlinked state directory")
	}
}

func mustMode(path string) os.FileMode {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Mode().Perm()
}

// Real C-locale lpstat output must authorize only the requested local queue.
func TestLocalUSBQueueParsesLPStatOutput(t *testing.T) {
	for _, test := range []struct {
		output  string
		allowed bool
	}{
		{"device for queue: usb://Zebra/ZD421?serial=fixture\n", true},
		{"device for other: usb://Zebra/ZD421?serial=fixture\n", false},
		{"device for queue: ipp://printer.example/ipp/print\n", false},
		{"device for queue: usb://Zebra/fixture\ndevice for other: usb://Zebra/other\n", false},
	} {
		got := localUSBQueue(context.Background(), outputRunner(test.output), "queue")
		if got != test.allowed {
			t.Fatalf("output %q: allowed=%v", test.output, got)
		}
	}
}

type outputRunner string

func (runner outputRunner) Run(context.Context, string, []string, []string) ([]byte, []byte, error) {
	return []byte(runner), nil, nil
}

// A reason continuation is valid; a second printer header cannot authorize state.
func TestQueueEnabledAcceptsStoppedReasonAndRejectsAdditionalRecords(t *testing.T) {
	for _, test := range []struct {
		output  string
		enabled bool
		valid   bool
	}{
		{"printer queue disabled since Tue Aug 27 01:00:00 2026 -\n\tPaused from NOVA Kiosk\n", false, true},
		{"printer queue is idle. enabled since Tue Aug 27 01:00:00 2026\n", true, true},
		{"printer queue disabled since Tue Aug 27 01:00:00 2026 -\nprinter other is idle. enabled since Tue Aug 27 01:00:00 2026\n", false, false},
		{"printer other disabled since Tue Aug 27 01:00:00 2026 -\n\tPaused\n", false, false},
	} {
		enabled, err := queueEnabled(context.Background(), outputRunner(test.output), "queue")
		if (err == nil) != test.valid || enabled != test.enabled {
			t.Fatalf("output %q: enabled=%v err=%v", test.output, enabled, err)
		}
	}
}

func TestManifestDefaultsDoNotChangeQueueAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		queues []string
		extra  bool
		want   bool
	}{
		{"owned", []string{"queue"}, false, true},
		{"defaults-only", []string{}, false, false},
		{"unknown-field", []string{"queue"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "print-bridge.json")
			value := map[string]any{"version": 2, "queues": test.queues, "settings": map[string][]string{"queue": {"PageSize"}}, "defaults": map[string]map[string]string{"queue": {"PageSize": "A4"}}}
			if test.extra {
				value["unexpected"] = true
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if got := manifestOwnsQueue(path, "queue"); got != test.want {
				t.Fatalf("authorization = %t, want %t", got, test.want)
			}
		})
	}
}

func TestQueueControlRejectsOptionNames(t *testing.T) {
	for _, name := range []string{"-a", "-h", "--help"} {
		request := validQueueRequest(ActionCancelAll)
		request.QueueName = name
		if request.Validate("kiosk") == nil || SafeQueueName(name) {
			t.Fatalf("option accepted as queue: %q", name)
		}
	}
}

func TestQueueEvidenceUsesCUPSCaseInsensitiveNames(t *testing.T) {
	if enabled, err := queueEnabled(t.Context(), outputRunner("printer QUEUE is idle.\n"), "queue"); err != nil || !enabled {
		t.Fatalf("case alias lost: %v", err)
	}
	if !localUSBQueue(t.Context(), outputRunner("device for QUEUE: usb://Zebra/serial\n"), "queue") {
		t.Fatal("USB alias rejected")
	}
	if active, err := activeJob(t.Context(), outputRunner("QUEUE-7 user 30\n"), "queue", 7); err != nil || !active {
		t.Fatalf("active alias lost: %v", err)
	}
	for _, output := range []string{"other-7 user 30\n", "queue-7 user 30\ninvalid\n", "queue-7-extra user 30\n"} {
		if _, err := activeJob(t.Context(), outputRunner(output), "queue", 7); err == nil {
			t.Fatalf("ambiguous evidence accepted: %q", output)
		}
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"version":2,"queues":["QUEUE"],"settings":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !manifestOwnsQueue(path, "queue") {
		t.Fatal("owned alias rejected")
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"queues":["QUEUE","queue"],"settings":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if manifestOwnsQueue(path, "queue") {
		t.Fatal("duplicate alias accepted")
	}
}

type deleteQueueRunner struct {
	calls     [][]string
	uri       string
	remaining string
	deleteErr error
	listErr   error
}

func (r *deleteQueueRunner) Run(_ context.Context, path string, args []string, _ []string) ([]byte, []byte, error) {
	r.calls = append(r.calls, append([]string{path}, args...))
	if path == "/usr/bin/lpstat" && reflect.DeepEqual(args, []string{"-v", "queue"}) {
		return []byte("device for queue: " + r.uri + "\n"), nil, nil
	}
	if path == "/usr/sbin/lpadmin" && reflect.DeepEqual(args, []string{"-x", "queue"}) {
		return nil, nil, r.deleteErr
	}
	if path == "/usr/bin/lpstat" && reflect.DeepEqual(args, []string{"-e"}) {
		return []byte(r.remaining), nil, r.listErr
	}
	return nil, nil, errors.New("unexpected command")
}

func TestUSBQueueDeletionRequiresAuthorityAndVerifiedRemoval(t *testing.T) {
	for _, tc := range []struct {
		name, uri, remaining string
		deleteErr, listErr   error
		applied              bool
		calls                int
	}{
		{name: "deleted last queue", uri: "usb://Zebra/serial", applied: true, calls: 3},
		{name: "other queues preserved", uri: "usb://Zebra/serial", remaining: "other\n", applied: true, calls: 3},
		{name: "not USB", uri: "socket://192.168.1.2", calls: 1},
		{name: "still exists", uri: "usb://Zebra/serial", remaining: "QuEuE\n", calls: 3},
		{name: "delete failed", uri: "usb://Zebra/serial", deleteErr: errors.New("failed"), calls: 2},
		{name: "postcheck failed", uri: "usb://Zebra/serial", listErr: errors.New("unavailable"), calls: 3},
		{name: "malformed postcheck", uri: "usb://Zebra/serial", remaining: "invalid output\n", calls: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &deleteQueueRunner{uri: tc.uri, remaining: tc.remaining, deleteErr: tc.deleteErr, listErr: tc.listErr}
			request := validQueueRequest(ActionDelete)
			if err := request.Validate("kiosk"); err != nil {
				t.Fatal(err)
			}
			result := runQueueAction(context.Background(), HelperConfig{Profile: "kiosk"}, r, request)
			if (result.Result == ResultApplied) != tc.applied || len(r.calls) != tc.calls {
				t.Fatalf("result=%+v calls=%v", result, r.calls)
			}
			if err := result.Validate("kiosk"); err != nil {
				t.Fatal(err)
			}
		})
	}
	request := validQueueRequest(ActionDelete)
	request.Profile = "print-bridge"
	if request.Validate("print-bridge") == nil {
		t.Fatal("bridge deletion bypasses desired state")
	}
	request.Profile = "kiosk"
	request.QueueName = "nvsprint1"
	r := &deleteQueueRunner{uri: "usb://Zebra/serial"}
	result := runQueueAction(context.Background(), HelperConfig{Profile: "kiosk"}, r, request)
	if result.Result != ResultFailed || len(r.calls) != 0 {
		t.Fatalf("reserved queue deleted: %+v", result)
	}
}
