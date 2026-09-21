// Package cupsjob implements authorized CUPS job cancellation and queue control
// through fixed commands in a privileged helper.
package cupsjob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	Version          = 1
	RequestType      = "printer.job.command"
	ResultType       = "printer.job.command.result"
	QueueRequestType = "printer.queue.command"
	QueueResultType  = "printer.queue.command.result"
	ActionCancel     = "cancel"
	ActionPause      = "pause"
	ActionResume     = "resume"
	ActionCancelAll  = "cancel-all"
	ActionDelete     = "delete"
	ActionAddUSB     = "add-usb"
	ResultApplied    = "applied"
	ResultFailed     = "failed"

	ErrorNotActive       = "not-active"
	ErrorPermission      = "permission-denied"
	ErrorHelper          = "helper-unavailable"
	ErrorTimeout         = "timeout"
	ErrorCommandFailed   = "command-failed"
	ErrorInvalid         = "invalid"
	ErrorQueueNotAllowed = "queue-not-allowed"

	RequestFileName        = "cups-job-request.json"
	ResultFileName         = "cups-job-result.json"
	MaxMessageBytes        = 16 * 1024
	MaxQueueBytes          = 127
	MaxJobID        uint64 = 2_147_483_647
	defaultTimeout         = 5 * time.Second
)

var queuePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Request struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	Profile     string `json:"profile"`
	Action      string `json:"action"`
	CommandHash string `json:"commandHash"`
	QueueName   string `json:"queueName"`
	CUPSJobID   uint64 `json:"cupsJobId,omitempty"`
}

type Result struct {
	Version      int     `json:"version"`
	Type         string  `json:"type"`
	Profile      string  `json:"profile"`
	Action       string  `json:"action"`
	CommandHash  string  `json:"commandHash"`
	QueueName    string  `json:"queueName"`
	CUPSJobID    uint64  `json:"cupsJobId,omitempty"`
	Result       string  `json:"result"`
	Error        string  `json:"errorCategory,omitempty"`
	AffectedJobs *uint64 `json:"affectedJobs,omitempty"`
}

func (request Request) Validate(profile string) error {
	if request.Version != Version || request.Profile != profile || (profile != "kiosk" && profile != "print-bridge") || !SafeQueueName(request.QueueName) || !hashPattern.MatchString(request.CommandHash) {
		return errors.New("invalid CUPS job request")
	}
	if request.Type == RequestType && request.Action == ActionCancel && request.CUPSJobID >= 1 && request.CUPSJobID <= MaxJobID {
		return nil
	}
	if request.Type == QueueRequestType && (request.Action == ActionPause || request.Action == ActionResume || request.Action == ActionCancelAll || (request.Action == ActionDelete || request.Action == ActionAddUSB) && profile == "kiosk") && request.CUPSJobID == 0 {
		return nil
	}
	return errors.New("invalid CUPS job request")
}

func (result Result) Validate(profile string) error {
	if result.Version != Version || result.Profile != profile || !SafeQueueName(result.QueueName) || !hashPattern.MatchString(result.CommandHash) || (result.Result != ResultApplied && result.Result != ResultFailed) {
		return errors.New("invalid CUPS job result")
	}
	if result.Type == ResultType && result.Action == ActionCancel && result.CUPSJobID >= 1 && result.CUPSJobID <= MaxJobID && result.AffectedJobs == nil {
		// Valid job result.
	} else if result.Type == QueueResultType && (result.Action == ActionPause || result.Action == ActionResume || (result.Action == ActionDelete || result.Action == ActionAddUSB) && profile == "kiosk") && result.CUPSJobID == 0 && result.AffectedJobs == nil {
		// Valid queue-state result.
	} else if result.Type == QueueResultType && result.Action == ActionCancelAll && result.CUPSJobID == 0 && result.AffectedJobs != nil {
		// Valid queue cancellation result.
	} else {
		return errors.New("invalid CUPS job result")
	}
	if result.Result == ResultApplied && result.Error != "" {
		return errors.New("applied CUPS job result has an error")
	}
	if result.Result == ResultFailed {
		switch result.Error {
		case ErrorNotActive, ErrorPermission, ErrorHelper, ErrorTimeout, ErrorCommandFailed, ErrorInvalid, ErrorQueueNotAllowed:
		default:
			return errors.New("invalid CUPS job result error")
		}
	}
	return nil
}

type CommandRunner interface {
	Run(context.Context, string, []string, []string) ([]byte, []byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, path string, args []string, env []string) ([]byte, []byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, path, args...)
	command.Env = append([]string{"LC_ALL=C", "LANG=C", "TZ=UTC", "PATH=/usr/bin:/usr/sbin"}, env...)
	var stdout, stderr boundedBuffer
	stdout.max, stderr.max = 8*1024, 4*1024
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if commandCtx.Err() != nil {
		return nil, nil, commandCtx.Err()
	}
	if stdout.overflow || stderr.overflow {
		return nil, nil, errors.New("CUPS job command output exceeded bound")
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

type CancelClient struct {
	StateDir string
	Profile  string
	Runner   CommandRunner
}

func ProfilePaths(profile string) (stateDir, manifestDir string, ok bool) {
	switch profile {
	case "kiosk":
		return "/var/lib/novakiosk-agent", "/var/lib/novakiosk-cups-helper", true
	case "print-bridge":
		return "/var/lib/novakiosk-print-bridge", "/var/lib/novakiosk-cups-helper", true
	default:
		return "", "", false
	}
}

func (client CancelClient) Cancel(ctx context.Context, request Request) (Result, error) {
	if request.Type != RequestType {
		return failureFor(request, ErrorInvalid), errors.New("invalid CUPS job cancel request")
	}
	return client.apply(ctx, request)
}

func (client CancelClient) ControlQueue(ctx context.Context, request Request) (Result, error) {
	if request.Type != QueueRequestType {
		return failureFor(request, ErrorInvalid), errors.New("invalid CUPS queue control request")
	}
	return client.apply(ctx, request)
}

func (client CancelClient) apply(ctx context.Context, request Request) (Result, error) {
	if ctx == nil || client.Runner == nil && client.StateDir == "" || request.Validate(client.Profile) != nil || validatePrivateDirectory(client.StateDir) != nil {
		return failureFor(request, ErrorInvalid), errors.New("invalid CUPS command client")
	}
	requestPath := filepath.Join(client.StateDir, RequestFileName)
	resultPath := filepath.Join(client.StateDir, ResultFileName)
	data, err := json.Marshal(request)
	if err != nil || len(data) > MaxMessageBytes {
		return failureFor(request, ErrorInvalid), err
	}
	if err := saveAtomic(client.StateDir, requestPath, data); err != nil {
		return failureFor(request, ErrorHelper), err
	}
	_ = os.Remove(resultPath)
	runner := client.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	if _, _, err := runner.Run(ctx, "/usr/bin/systemctl", []string{"start", "novakiosk-cups-job@" + client.Profile + ".service"}, nil); err != nil {
		return failureFor(request, ErrorHelper), err
	}
	result, err := loadResult(resultPath, request)
	if err != nil {
		return failureFor(request, ErrorHelper), err
	}
	return result, nil
}

func failureFor(request Request, category string) Result {
	resultType := ResultType
	if request.Type == QueueRequestType {
		resultType = QueueResultType
	}
	result := Result{Version: Version, Type: resultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, CUPSJobID: request.CUPSJobID, Result: ResultFailed, Error: category}
	if request.Action == ActionCancelAll {
		zero := uint64(0)
		result.AffectedJobs = &zero
	}
	return result
}

type HelperConfig struct {
	StateDir    string
	ManifestDir string
	Profile     string
	Runner      CommandRunner
	Timeout     time.Duration
}

func ApplyHelper(ctx context.Context, config HelperConfig) error {
	if ctx == nil || os.Geteuid() != 0 || (config.Profile != "kiosk" && config.Profile != "print-bridge") || validatePrivateDirectory(config.StateDir) != nil {
		return errors.New("invalid CUPS job helper profile")
	}
	if config.ManifestDir == "" {
		config.ManifestDir = "/var/lib/novakiosk-cups-helper"
	}
	if err := validatePrivateDirectory(config.ManifestDir); err != nil {
		return err
	}
	// Reuse the reconcile profile lock: manifest ownership and cancellation
	// authority are one serialized operation, even though request/result files
	// remain separate from reconcile's protocol files.
	lock, err := acquireLock(filepath.Join(config.ManifestDir, config.Profile+".lock"))
	if err != nil {
		return err
	}
	defer releaseLock(lock)
	requestPath := filepath.Join(config.StateDir, RequestFileName)
	resultPath := filepath.Join(config.StateDir, ResultFileName)
	request, err := loadRequest(requestPath, config.Profile)
	if err != nil {
		// There is no trustworthy queue, job id, or command hash to echo for a
		// malformed request. Leave no syntactically plausible result behind;
		// the unprivileged client will report the bounded helper-unavailable
		// category and the request can be diagnosed without leaking input.
		return err
	}
	runner := config.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	var result Result
	if request.Type == QueueRequestType {
		result = runQueueAction(ctx, config, runner, request)
	} else {
		result = runCancel(ctx, config, runner, request)
	}
	return writeResult(resultPath, result)
}

func authorizeQueue(ctx context.Context, config HelperConfig, runner CommandRunner, queue string) bool {
	if config.Profile == "print-bridge" {
		return manifestOwnsQueue(filepath.Join(config.ManifestDir, "print-bridge.json"), queue)
	}
	return localUSBQueue(ctx, runner, queue)
}

func runCancel(ctx context.Context, config HelperConfig, runner CommandRunner, request Request) Result {
	failure := failureFor(request, ErrorCommandFailed)
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		config.Timeout = defaultTimeout
	}
	if !authorizeQueue(ctx, config, runner, request.QueueName) {
		failure.Error = ErrorQueueNotAllowed
		return failure
	}
	jobToken := request.QueueName + "-" + strconv.FormatUint(request.CUPSJobID, 10)
	active, err := activeJob(ctx, runner, request.QueueName, request.CUPSJobID)
	if err != nil {
		failure.Error = classifyHelperError(err)
		return failure
	}
	if !active {
		failure.Error = ErrorNotActive
		return failure
	}
	if _, _, err = runner.Run(ctx, "/usr/bin/cancel", []string{jobToken}, nil); err != nil {
		// A cancel exit status is not proof that the job remained active: CUPS
		// can report a race while another worker removes the job. Make one
		// bounded, exact postcheck to distinguish that case, without ever
		// retrying the destructive command.
		activeAfterFailure, checkErr := activeJob(ctx, runner, request.QueueName, request.CUPSJobID)
		if checkErr != nil {
			failure.Error = classifyHelperError(checkErr)
			return failure
		}
		if !activeAfterFailure {
			failure.Error = ErrorNotActive
			return failure
		}
		failure.Error = classifyHelperError(err)
		return failure
	}
	deadline := time.Now().Add(config.Timeout)
	for time.Now().Before(deadline) {
		active, checkErr := activeJob(ctx, runner, request.QueueName, request.CUPSJobID)
		if checkErr != nil {
			failure.Error = classifyHelperError(checkErr)
			return failure
		}
		if !active {
			return Result{Version: Version, Type: ResultType, Profile: request.Profile, Action: ActionCancel, CommandHash: request.CommandHash, QueueName: request.QueueName, CUPSJobID: request.CUPSJobID, Result: ResultApplied}
		}
		select {
		case <-ctx.Done():
			failure.Error = ErrorTimeout
			return failure
		case <-time.After(100 * time.Millisecond):
		}
	}
	failure.Error = ErrorTimeout
	return failure
}

func runQueueAction(ctx context.Context, config HelperConfig, runner CommandRunner, request Request) Result {
	if request.Action == ActionAddUSB {
		return addUSBQueue(ctx, config, runner, request)
	}
	failure := failureFor(request, ErrorCommandFailed)
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		config.Timeout = defaultTimeout
	}
	if !authorizeQueue(ctx, config, runner, request.QueueName) {
		failure.Error = ErrorQueueNotAllowed
		return failure
	}
	switch request.Action {
	case ActionDelete:
		// Only local USB queues are deletable here. Managed bridge removal uses reconcile.
		if config.Profile != "kiosk" {
			failure.Error = ErrorQueueNotAllowed
			return failure
		}
		if _, _, err := runner.Run(ctx, "/usr/sbin/lpadmin", []string{"-x", request.QueueName}, nil); err != nil {
			failure.Error = classifyHelperError(err)
			return failure
		}
		stdout, _, err := runner.Run(ctx, "/usr/bin/lpstat", []string{"-e"}, nil)
		if err != nil {
			failure.Error = classifyHelperError(err)
			return failure
		}
		for line := range strings.SplitSeq(strings.ReplaceAll(string(stdout), "\r\n", "\n"), "\n") {
			if strings.ContainsAny(line, " \t\r\x00") || strings.EqualFold(line, request.QueueName) {
				return failure
			}
		}
		return Result{Version: Version, Type: QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: ResultApplied}
	case ActionPause, ActionResume:
		enabled, err := queueEnabled(ctx, runner, request.QueueName)
		if err != nil {
			failure.Error = classifyHelperError(err)
			return failure
		}
		wantEnabled := request.Action == ActionResume
		if enabled == wantEnabled {
			return Result{Version: Version, Type: QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: ResultApplied}
		}
		path, args := "/usr/sbin/cupsenable", []string{request.QueueName}
		if request.Action == ActionPause {
			path, args = "/usr/sbin/cupsdisable", []string{"-r", "Paused from NOVA Kiosk", request.QueueName}
		}
		if _, _, err = runner.Run(ctx, path, args, nil); err != nil {
			failure.Error = classifyHelperError(err)
			return failure
		}
		deadline := time.Now().Add(config.Timeout)
		for time.Now().Before(deadline) {
			enabled, err = queueEnabled(ctx, runner, request.QueueName)
			if err != nil {
				failure.Error = classifyHelperError(err)
				return failure
			}
			if enabled == wantEnabled {
				return Result{Version: Version, Type: QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: ResultApplied}
			}
			if !waitForPostcheck(ctx) {
				failure.Error = ErrorTimeout
				return failure
			}
		}
	case ActionCancelAll:
		initial, err := activeQueueJobIDs(ctx, runner, request.QueueName)
		if err != nil {
			failure.Error = classifyHelperError(err)
			return failure
		}
		count := uint64(len(initial))
		if len(initial) == 0 {
			return Result{Version: Version, Type: QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: ResultApplied, AffectedJobs: &count}
		}
		_, _, commandErr := runner.Run(ctx, "/usr/bin/cancel", []string{"-a", request.QueueName}, nil)
		deadline := time.Now().Add(config.Timeout)
		for time.Now().Before(deadline) {
			current, err := activeQueueJobIDs(ctx, runner, request.QueueName)
			if err != nil {
				failure.Error = classifyHelperError(err)
				return failure
			}
			if !containsAnyJob(current, initial) {
				return Result{Version: Version, Type: QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: ResultApplied, AffectedJobs: &count}
			}
			if commandErr != nil {
				failure.Error = classifyHelperError(commandErr)
				return failure
			}
			if !waitForPostcheck(ctx) {
				failure.Error = ErrorTimeout
				return failure
			}
		}
	default:
		failure.Error = ErrorInvalid
		return failure
	}
	failure.Error = ErrorTimeout
	return failure
}

func waitForPostcheck(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(100 * time.Millisecond):
		return true
	}
}

func queueEnabled(ctx context.Context, runner CommandRunner, queue string) (bool, error) {
	stdout, _, err := runner.Run(ctx, "/usr/bin/lpstat", []string{"-p", queue}, nil)
	if err != nil {
		return false, err
	}
	if len(stdout) == 0 || len(stdout) > 8*1024 {
		return false, errors.New("queue state unavailable")
	}
	text := strings.TrimSuffix(strings.ReplaceAll(string(stdout), "\r\n", "\n"), "\n")
	if text == "" || strings.ContainsAny(text, "\r\x00") {
		return false, errors.New("invalid queue state")
	}
	lines := strings.Split(text, "\n")
	line := lines[0]
	if strings.TrimSpace(line) != line {
		return false, errors.New("invalid queue state")
	}
	// lpstat prints a stopped printer's reason on an indented continuation.
	// Reject additional records rather than treating another queue as evidence.
	for _, detail := range lines[1:] {
		if !strings.HasPrefix(detail, "\t") || strings.TrimSpace(detail) == "" {
			return false, errors.New("invalid queue state detail")
		}
	}
	prefix := "printer " + queue + " "
	if len(line) < len(prefix) || !strings.EqualFold(line[:len(prefix)], prefix) {
		return false, errors.New("invalid queue state")
	}
	state := line[len(prefix):]
	if strings.HasPrefix(state, "disabled ") {
		return false, nil
	}
	if strings.HasPrefix(state, "is idle.") || strings.HasPrefix(state, "now printing ") {
		return true, nil
	}
	return false, errors.New("invalid queue state")
}

func activeQueueJobIDs(ctx context.Context, runner CommandRunner, queue string) (map[uint64]struct{}, error) {
	stdout, _, err := runner.Run(ctx, "/usr/bin/lpstat", []string{"-W", "not-completed", "-o", queue}, nil)
	if err != nil {
		return nil, err
	}
	if len(stdout) > 32*1024 {
		return nil, errors.New("active job output unavailable")
	}
	ids := make(map[uint64]struct{})
	for line := range strings.SplitSeq(strings.ReplaceAll(string(stdout), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		prefix := queue + "-"
		if len(fields[0]) <= len(prefix) || !strings.EqualFold(fields[0][:len(prefix)], prefix) {
			return nil, errors.New("invalid active job identity")
		}
		id, parseErr := strconv.ParseUint(fields[0][len(prefix):], 10, 64)
		if parseErr != nil || id == 0 || id > MaxJobID {
			return nil, errors.New("invalid active job identity")
		}
		ids[id] = struct{}{}
		if len(ids) > 4096 {
			return nil, errors.New("active job count exceeded bound")
		}
	}
	return ids, nil
}

func containsAnyJob(current, initial map[uint64]struct{}) bool {
	for id := range initial {
		if _, exists := current[id]; exists {
			return true
		}
	}
	return false
}

func activeJob(ctx context.Context, runner CommandRunner, queue string, id uint64) (bool, error) {
	ids, err := activeQueueJobIDs(ctx, runner, queue)
	if err != nil {
		return false, err
	}
	_, active := ids[id]
	return active, nil
}

func localUSBQueue(ctx context.Context, runner CommandRunner, queue string) bool {
	if strings.EqualFold(queue, "nvsprint1") {
		return false
	}
	stdout, _, err := runner.Run(ctx, "/usr/bin/lpstat", []string{"-v", queue}, nil)
	if err != nil || len(stdout) == 0 || len(stdout) > 8*1024 {
		return false
	}
	text := strings.ReplaceAll(string(stdout), "\r\n", "\n")
	if before, ok := strings.CutSuffix(text, "\n"); ok {
		text = before
	}
	if text == "" || strings.ContainsAny(text, "\r\n") || strings.TrimSpace(text) != text {
		return false
	}
	prefix := "device for " + queue + ": usb://"
	if len(text) < len(prefix) || !strings.EqualFold(text[:len(prefix)], prefix) {
		return false
	}
	uri := text[len(prefix):]
	return uri != "" && !strings.ContainsAny(uri, " \t\r\n\x00")
}

type manifest struct {
	Version  int                          `json:"version"`
	Queues   []string                     `json:"queues"`
	Claims   []string                     `json:"claims,omitempty"`
	Settings map[string][]string          `json:"settings"`
	Defaults map[string]map[string]string `json:"defaults,omitempty"`
}

func manifestOwnsQueue(path, queue string) bool {
	if strings.EqualFold(queue, "nvsprint1") {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false
	}
	// The helper runs as root in production. In that context only the
	// root-owned applied manifest can authorize a cancellation. The euid guard
	// remains conditional so package-level parser tests can use temp fixtures.
	if os.Geteuid() == 0 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 32*1024 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value manifest
	if decoder.Decode(&value) != nil || value.Version != 1 && value.Version != 2 || !SafeQueueName(queue) {
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return false
	}
	seen := make(map[string]struct{}, len(value.Queues))
	ownedQueue := false
	for _, owned := range value.Queues {
		if !SafeQueueName(owned) {
			return false
		}
		if _, exists := seen[strings.ToLower(owned)]; exists {
			return false
		}
		seen[strings.ToLower(owned)] = struct{}{}
		if strings.EqualFold(owned, queue) {
			ownedQueue = true
		}
	}
	return ownedQueue
}

func loadRequest(path, profile string) (Request, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return Request{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if decoder.Decode(&request) != nil || request.Validate(profile) != nil {
		return Request{}, errors.New("invalid CUPS job request")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Request{}, errors.New("invalid CUPS job request")
	}
	return request, nil
}

func loadResult(path string, request Request) (Result, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return Result{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result Result
	if decoder.Decode(&result) != nil || result.Validate(request.Profile) != nil || result.CommandHash != request.CommandHash || result.QueueName != request.QueueName || result.CUPSJobID != request.CUPSJobID || result.Action != request.Action {
		return Result{}, errors.New("invalid CUPS job result")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Result{}, errors.New("invalid CUPS job result")
	}
	return result, nil
}

func writeResult(path string, result Result) error {
	if result.Validate(result.Profile) != nil {
		return errors.New("invalid CUPS job result")
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > MaxMessageBytes {
		return errors.New("invalid CUPS job result")
	}
	directory := filepath.Dir(path)
	if err := validatePrivateDirectory(directory); err != nil {
		return err
	}
	// The oneshot is root-owned, while the long-running agent owns its state
	// directory.  Preserve that owner on the result so the agent can consume
	// it after systemd starts the helper.  Never derive an owner from request
	// data or follow a directory symlink.
	uid, gid := -1, -1
	if os.Geteuid() == 0 {
		info, statErr := os.Lstat(directory)
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			if statErr == nil {
				statErr = errors.New("unsafe CUPS job state directory")
			}
			return statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid == 0 {
			return errors.New("CUPS job state directory is not agent-owned")
		}
		uid, gid = int(stat.Uid), int(stat.Gid)
	}
	return saveAtomicOwned(directory, path, data, uid, gid)
}

func SafeQueueName(value string) bool {
	return len(value) >= 1 && value[0] != '-' && len(value) <= MaxQueueBytes && queuePattern.MatchString(value)
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("unsafe CUPS job state directory")
	}
	return nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > limit {
		return nil, errors.New("unsafe CUPS job state file")
	}
	return os.ReadFile(path)
}

func saveAtomic(directory, path string, data []byte) error {
	return saveAtomicOwned(directory, path, data, -1, -1)
}

func saveAtomicOwned(directory, path string, data []byte, uid, gid int) error {
	if err := validatePrivateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".cups-job-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if uid >= 0 || gid >= 0 {
		if uid < 0 || gid < 0 || temporary.Chown(uid, gid) != nil {
			_ = temporary.Close()
			return errors.New("could not assign CUPS job result owner")
		}
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func classifyHelperError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTimeout
	}
	if errors.Is(err, os.ErrPermission) {
		return ErrorPermission
	}
	return ErrorCommandFailed
}

func acquireLock(path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func releaseLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

type boundedBuffer struct {
	data     bytes.Buffer
	max      int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if buffer.data.Len()+len(value) > buffer.max {
		buffer.overflow = true
		return len(value), nil
	}
	return buffer.data.Write(value)
}
func (buffer *boundedBuffer) Bytes() []byte { return buffer.data.Bytes() }
