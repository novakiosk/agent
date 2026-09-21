package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

const (
	OperationVersion = 1
	OperationType    = "operation.result"

	DefaultCommandTimeout = 30 * time.Second
	DefaultUpdateTimeout  = 30 * time.Minute
	MaxOperationTimeout   = 1 * time.Hour
	DefaultMaxOutputBytes = 8 * 1024
	MaxResultJSONBytes    = 8 * 1024

	DefaultSystemctlPath  = "/usr/bin/systemctl"
	FallbackSystemctlPath = "/bin/systemctl"
	OstreeBootedPath      = "/run/ostree-booted"
	UpdateUnitPath        = "/usr/lib/systemd/system/novakiosk-system-update@.service"
	UpdateHelperPath      = "/usr/libexec/novakiosk-system-update"
	RPMOstreePath         = "/usr/bin/rpm-ostree"

	rpmOstreeFallback = "/bin/rpm-ostree"
)

type CommandType string

const (
	CommandReboot       CommandType = "reboot"
	CommandPoweroff     CommandType = "poweroff"
	CommandSystemUpdate CommandType = "system-update"
)

type OperationResultState string

const (
	ResultScheduled OperationResultState = "scheduled"
	ResultStaged    OperationResultState = "staged"
	ResultFailed    OperationResultState = "failed"
)

// ErrorCategory is a stable, deliberately small diagnostic vocabulary.  Raw
// process errors and command output never enter OperationResult.
type ErrorCategory string

const (
	ErrorInvalidCommand         ErrorCategory = "invalid_command"
	ErrorPreflightFailed        ErrorCategory = "preflight_failed"
	ErrorBootIDUnavailable      ErrorCategory = "boot_id_unavailable"
	ErrorSystemctlMissing       ErrorCategory = "systemctl_missing"
	ErrorUpdateUnitMissing      ErrorCategory = "update_unit_missing"
	ErrorUpdateHelperMissing    ErrorCategory = "update_helper_missing"
	ErrorRPMOstreeMissing       ErrorCategory = "rpm_ostree_missing"
	ErrorTimeout                ErrorCategory = "timeout"
	ErrorContextCanceled        ErrorCategory = "context_canceled"
	ErrorOutputLimit            ErrorCategory = "output_limit"
	ErrorBinaryMissing          ErrorCategory = "binary_missing"
	ErrorCommandFailed          ErrorCategory = "command_failed"
	ErrorFilesystem             ErrorCategory = "filesystem_error"
	ErrorExecutionInterrupted   ErrorCategory = "execution_interrupted"
	ErrorExecutionInvalidResult ErrorCategory = "execution_result_invalid"
	ErrorCommandExpired         ErrorCategory = "command_expired"
)

// OperationResult is the only output of Execute.  A successful reboot or
// poweroff means systemd accepted scheduling; a successful update means the
// helper staged an update.  Neither is evidence that a reboot happened or
// that an image booted/applied.
type OperationResult struct {
	Version       int                  `json:"version"`
	Type          string               `json:"type"`
	CommandType   CommandType          `json:"commandType"`
	Result        OperationResultState `json:"result"`
	ErrorCategory *ErrorCategory       `json:"errorCategory"`
	ObservedAt    string               `json:"observedAt"`
	BootIDBefore  string               `json:"bootIdBefore"`
}

// Runner is the only process-execution seam.  Tests can inspect exact path,
// argv, environment, and context deadline without executing a command.
type Runner interface {
	Run(context.Context, string, []string, []string) (stdout, stderr []byte, err error)
}

type RunnerFunc func(context.Context, string, []string, []string) ([]byte, []byte, error)

func (runner RunnerFunc) Run(ctx context.Context, path string, args []string, env []string) ([]byte, []byte, error) {
	return runner(ctx, path, args, env)
}

// OperationConfig controls the fixed executor.  SystemctlPath is for an
// explicitly resolved test/production path; when empty, construction checks
// /usr/bin/systemctl and then /bin/systemctl once, storing the selected path.
type OperationConfig struct {
	Runner         Runner
	Clock          func() time.Time
	FS             FileSystem
	SystemctlPath  string
	CommandTimeout time.Duration
	UpdateTimeout  time.Duration
	MaxOutputBytes int
}

// Executor executes only the three fixed operations.
type Executor struct {
	runner         Runner
	clock          func() time.Time
	fileSystem     FileSystem
	systemctlPath  string
	commandTimeout time.Duration
	updateTimeout  time.Duration
	maxOutputBytes int
	initErr        error
}

// NewExecutor constructs an executor without running a command.  Resolution
// of systemctl is intentionally performed once at construction, never via a
// shell or a later PATH lookup.
func NewExecutor(config ...OperationConfig) *Executor {
	c := OperationConfig{}
	if len(config) != 0 {
		c = config[0]
	}
	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}
	fileSystem := defaultFileSystem(c.FS)
	commandTimeout := boundedTimeout(c.CommandTimeout, DefaultCommandTimeout)
	updateTimeout := boundedTimeout(c.UpdateTimeout, DefaultUpdateTimeout)
	maxOutput := c.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutputBytes
	}
	if maxOutput > MaxResultJSONBytes {
		maxOutput = MaxResultJSONBytes
	}
	pathValue := strings.TrimSpace(c.SystemctlPath)
	var initErr error
	if pathValue == "" {
		pathValue, initErr = resolveSystemctl(fileSystem)
	} else if !safeSystemctlPath(pathValue) || (c.Runner == nil && pathValue != DefaultSystemctlPath && pathValue != FallbackSystemctlPath) {
		initErr = errors.New("operations: invalid systemctl path")
	}
	if c.Runner != nil {
		// An injected runner still receives an explicit path in tests.  The
		// production path remains fixed even when it was not present on host.
		if pathValue == "" {
			pathValue = DefaultSystemctlPath
		}
	}
	return &Executor{
		runner: c.Runner, clock: clock, fileSystem: fileSystem,
		systemctlPath: pathValue, commandTimeout: commandTimeout,
		updateTimeout: updateTimeout, maxOutputBytes: maxOutput, initErr: initErr,
	}
}

func boundedTimeout(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	if value > MaxOperationTimeout {
		return MaxOperationTimeout
	}
	return value
}

func safeSystemctlPath(value string) bool {
	if !safeAbsolutePath(value) || path.Base(value) != "systemctl" {
		return false
	}
	return true
}

func resolveSystemctl(fileSystem FileSystem) (string, error) {
	if executablePresent(fileSystem, DefaultSystemctlPath) {
		return DefaultSystemctlPath, nil
	}
	if executablePresent(fileSystem, FallbackSystemctlPath) {
		return FallbackSystemctlPath, nil
	}
	return "", errors.New("operations: systemctl is missing")
}

// Execute performs one operation.  It never retries and never chains an
// update into a reboot.
func (executor *Executor) Execute(ctx context.Context, commandType CommandType) OperationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if executor == nil {
		result := OperationResult{Version: OperationVersion, Type: OperationType, CommandType: commandType, Result: ResultFailed, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		result.ErrorCategory = errorCategoryPointer(ErrorFilesystem)
		return result
	}
	result := OperationResult{
		Version: OperationVersion, Type: OperationType, CommandType: commandType,
		Result: ResultFailed, ObservedAt: executor.timestamp(),
	}
	if !validCommandType(commandType) {
		result.ErrorCategory = errorCategoryPointer(ErrorInvalidCommand)
		return result
	}
	bootID, bootErr := executor.readBootID()
	result.BootIDBefore = bootID
	if bootErr != nil {
		result.ErrorCategory = errorCategoryPointer(ErrorBootIDUnavailable)
		return result
	}
	if executor.initErr != nil && executor.runner == nil {
		result.ErrorCategory = errorCategoryPointer(categoryForInitError(executor.initErr))
		return result
	}
	if commandType == CommandSystemUpdate {
		if category := executor.updatePreflight(); category != "" {
			result.ErrorCategory = errorCategoryPointer(category)
			return result
		}
	}

	runner := executor.runner
	if runner == nil {
		runner = productionRunner{maxOutputBytes: executor.maxOutputBytes}
	}
	args := fixedArguments(commandType)
	timeout := executor.commandTimeout
	if commandType == CommandSystemUpdate {
		timeout = executor.updateTimeout
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, _, err := runner.Run(commandCtx, executor.systemctlPath, args, []string{"LC_ALL=C", "LANG=C"})
	if err != nil {
		result.ErrorCategory = errorCategoryPointer(classifyOperationError(err, commandCtx, ctx))
		return result
	}
	if commandCtx.Err() != nil {
		result.ErrorCategory = errorCategoryPointer(classifyOperationError(commandCtx.Err(), commandCtx, ctx))
		return result
	}
	if commandType == CommandSystemUpdate {
		result.Result = ResultStaged
	} else {
		result.Result = ResultScheduled
	}
	return result
}

func (executor *Executor) timestamp() string {
	clock := time.Now
	if executor != nil && executor.clock != nil {
		clock = executor.clock
	}
	return clock().UTC().Format(time.RFC3339Nano)
}

func (executor *Executor) readBootID() (string, error) {
	if executor == nil || executor.fileSystem == nil {
		return "", errors.New("filesystem unavailable")
	}
	value, err := executor.fileSystem.ReadFile(BootIDPath)
	if err != nil {
		return "", err
	}
	return canonicalBootID(string(value))
}

func (executor *Executor) updatePreflight() ErrorCategory {
	if executor == nil || executor.fileSystem == nil {
		return ErrorPreflightFailed
	}
	if !filePresent(executor.fileSystem, OstreeBootedPath) {
		return ErrorPreflightFailed
	}
	if !filePresent(executor.fileSystem, UpdateUnitPath) {
		return ErrorUpdateUnitMissing
	}
	if !executablePresent(executor.fileSystem, UpdateHelperPath) {
		return ErrorUpdateHelperMissing
	}
	if !executablePresent(executor.fileSystem, RPMOstreePath) && !executablePresent(executor.fileSystem, rpmOstreeFallback) {
		return ErrorRPMOstreeMissing
	}
	return ""
}

func fixedArguments(commandType CommandType) []string {
	switch commandType {
	case CommandReboot:
		return []string{"reboot"}
	case CommandPoweroff:
		return []string{"poweroff"}
	case CommandSystemUpdate:
		return []string{"start", "--wait", "novakiosk-system-update@rpm-ostree.service"}
	default:
		return nil
	}
}

func validCommandType(commandType CommandType) bool {
	return commandType == CommandReboot || commandType == CommandPoweroff || commandType == CommandSystemUpdate
}

func categoryForInitError(err error) ErrorCategory {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "systemctl") {
		return ErrorSystemctlMissing
	}
	return ErrorFilesystem
}

func classifyOperationError(err error, commandCtx, parent context.Context) ErrorCategory {
	if errors.Is(err, errOperationOutputLimit) {
		return ErrorOutputLimit
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(commandCtx.Err(), context.DeadlineExceeded) || errors.Is(parent.Err(), context.DeadlineExceeded) {
		return ErrorTimeout
	}
	if errors.Is(err, context.Canceled) || errors.Is(commandCtx.Err(), context.Canceled) || errors.Is(parent.Err(), context.Canceled) {
		return ErrorContextCanceled
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return ErrorBinaryMissing
	}
	return ErrorCommandFailed
}

func errorCategoryPointer(category ErrorCategory) *ErrorCategory {
	if category == "" {
		return nil
	}
	value := category
	return &value
}

func validErrorCategory(category ErrorCategory) bool {
	switch category {
	case ErrorInvalidCommand, ErrorPreflightFailed, ErrorBootIDUnavailable, ErrorSystemctlMissing,
		ErrorUpdateUnitMissing, ErrorUpdateHelperMissing, ErrorRPMOstreeMissing, ErrorTimeout,
		ErrorContextCanceled, ErrorOutputLimit, ErrorBinaryMissing, ErrorCommandFailed, ErrorFilesystem,
		ErrorExecutionInterrupted, ErrorExecutionInvalidResult, ErrorCommandExpired:
		return true
	default:
		return false
	}
}

func validResultState(value OperationResultState) bool {
	return value == ResultScheduled || value == ResultStaged || value == ResultFailed
}

// Validate enforces the result schema and prevents a successful state from
// ever being named succeeded/applied/booted.
func (result OperationResult) Validate() error {
	if result.Version != OperationVersion || result.Type != OperationType {
		return errors.New("operations: invalid result version or type")
	}
	if !validCommandType(result.CommandType) {
		return errors.New("operations: invalid commandType")
	}
	state := result.Result
	if !validResultState(state) {
		return errors.New("operations: invalid result")
	}
	if err := validateTimestamp(result.ObservedAt); err != nil {
		return fmt.Errorf("operations: observedAt: %w", err)
	}
	if result.BootIDBefore != "" {
		bootID, err := canonicalBootID(result.BootIDBefore)
		if err != nil || bootID != result.BootIDBefore {
			return errors.New("operations: non-canonical bootIdBefore")
		}
	}
	if result.ErrorCategory != nil && !validErrorCategory(*result.ErrorCategory) {
		return errors.New("operations: invalid errorCategory")
	}
	if state == ResultFailed {
		if result.ErrorCategory == nil {
			return errors.New("operations: failed result requires errorCategory")
		}
	} else {
		if result.ErrorCategory != nil {
			return errors.New("operations: successful result cannot have errorCategory")
		}
		if (result.CommandType == CommandSystemUpdate && state != ResultStaged) ||
			(result.CommandType != CommandSystemUpdate && state != ResultScheduled) {
			return errors.New("operations: result does not match commandType")
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("operations: marshal result: %w", err)
	}
	if len(encoded) > MaxResultJSONBytes {
		return fmt.Errorf("operations: result exceeds %d bytes", MaxResultJSONBytes)
	}
	return nil
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

var errOperationOutputLimit = errors.New("operations: command output limit")

type boundedOutput struct {
	data     bytes.Buffer
	max      int
	overflow bool
}

func (output *boundedOutput) Write(value []byte) (int, error) {
	if output.max <= 0 || len(value) > output.max-output.data.Len() {
		output.overflow = true
		remaining := output.max - output.data.Len()
		if remaining > 0 {
			_, _ = output.data.Write(value[:remaining])
		}
		return len(value), errOperationOutputLimit
	}
	return output.data.Write(value)
}

type productionRunner struct{ maxOutputBytes int }

func (runner productionRunner) Run(ctx context.Context, commandPath string, args []string, env []string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, commandPath, args...)
	// The executor passes C locale explicitly.  Env is not inherited, which
	// prevents user PATH/locale settings from changing command behavior.
	command.Env = append([]string(nil), env...)
	var stdout, stderr boundedOutput
	stdout.max, stderr.max = runner.maxOutputBytes, runner.maxOutputBytes
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, nil, errOperationOutputLimit
	}
	return nil, nil, err
}
