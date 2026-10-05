package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	OperationJournalVersion  = 1
	OperationJournalType     = "operation.journal"
	OperationJournalName     = "operation-command.json"
	MaxOperationJournalBytes = 8 * 1024
)

type JournalPhase string

const (
	PhaseAccepted         JournalPhase = "accepted"
	PhaseExecutionStarted JournalPhase = "execution_started"
	PhaseExecuted         JournalPhase = "executed"
	PhaseResultAccepted   JournalPhase = "result_accepted"
)

type AcceptanceStatus string

const (
	AcceptanceAccepted  AcceptanceStatus = "accepted"
	AcceptanceDuplicate AcceptanceStatus = "duplicate"
)

var (
	ErrCommandBusy     = errors.New("operations: another command is active")
	ErrCommandConflict = errors.New("operations: command conflicts with stored command")
	ErrNoCommand       = errors.New("operations: no stored command")
	ErrNoResult        = errors.New("operations: no stored result")
	ErrCommandNotReady = errors.New("operations: command is not ready for execution")
	ErrCommandNotFound = errors.New("operations: command does not match stored command")
)

// CommandExecutor is intentionally narrower than a generic command runner:
// the coordinator supplies only the already-validated fixed CommandType.
type CommandExecutor interface {
	Execute(context.Context, CommandType) OperationResult
}

type CoordinatorConfig struct {
	StateDir string
	Executor CommandExecutor
	Clock    func() time.Time
}

type CommandAcceptance struct {
	Status  AcceptanceStatus
	Phase   JournalPhase
	Command Command
	Result  *OperationResult
}

type operationJournal struct {
	Version int              `json:"version"`
	Type    string           `json:"type"`
	Phase   JournalPhase     `json:"phase"`
	Command Command          `json:"command"`
	Result  *OperationResult `json:"result,omitempty"`
}

type Coordinator struct {
	mu            sync.Mutex
	stateDir      string
	journalPath   string
	executor      CommandExecutor
	clock         func() time.Time
	journal       *operationJournal
	pendingResult *OperationResult
}

func OperationJournalPath(stateDir string) string {
	return filepath.Join(stateDir, OperationJournalName)
}

// NewCoordinator validates the already-existing private state directory and
// loads one bounded journal. It never creates or chmods the directory.
func NewCoordinator(config CoordinatorConfig) (*Coordinator, error) {
	if strings.TrimSpace(config.StateDir) == "" {
		return nil, errors.New("operations: state directory is required")
	}
	if config.Executor == nil {
		return nil, errors.New("operations: fixed executor is required")
	}
	if err := validateStateDirectory(config.StateDir); err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	coordinator := &Coordinator{
		stateDir: config.StateDir, journalPath: OperationJournalPath(config.StateDir),
		executor: config.Executor, clock: clock,
	}
	journal, err := loadOperationJournal(coordinator.journalPath, clock())
	if err != nil {
		return nil, err
	}
	coordinator.journal = journal
	if journal != nil && journal.Phase == PhaseExecutionStarted && journal.Result == nil {
		if err := coordinator.recoverInterruptedLocked(journal); err != nil {
			return nil, err
		}
	}
	return coordinator, nil
}

func (coordinator *Coordinator) Accept(command Command) (CommandAcceptance, error) {
	if coordinator == nil {
		return CommandAcceptance{}, errors.New("operations: nil coordinator")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.journal == nil {
		if err := command.Validate(coordinator.clock()); err != nil {
			return CommandAcceptance{}, err
		}
		journal := &operationJournal{Version: OperationJournalVersion, Type: OperationJournalType, Phase: PhaseAccepted, Command: command}
		if err := coordinator.persistLocked(journal); err != nil {
			return CommandAcceptance{}, err
		}
		coordinator.journal = journal
		return CommandAcceptance{Status: AcceptanceAccepted, Phase: PhaseAccepted, Command: command}, nil
	}
	current := coordinator.journal
	if current.Command.CommandID == command.CommandID {
		if !SameCommand(current.Command, command) {
			return CommandAcceptance{}, ErrCommandConflict
		}
		return CommandAcceptance{Status: AcceptanceDuplicate, Phase: current.Phase, Command: current.Command, Result: cloneResult(current.Result)}, nil
	}
	if current.Phase != PhaseResultAccepted {
		return CommandAcceptance{}, ErrCommandBusy
	}
	if err := command.Validate(coordinator.clock()); err != nil {
		return CommandAcceptance{}, err
	}
	journal := &operationJournal{Version: OperationJournalVersion, Type: OperationJournalType, Phase: PhaseAccepted, Command: command}
	if err := coordinator.persistLocked(journal); err != nil {
		return CommandAcceptance{}, err
	}
	coordinator.journal = journal
	return CommandAcceptance{Status: AcceptanceAccepted, Phase: PhaseAccepted, Command: command}, nil
}

// ExecuteOnce persists execution_started before invoking the fixed executor.
// Later calls retry a pending result commit or replay the durable result,
// without invoking the executor again.
func (coordinator *Coordinator) ExecuteOnce(ctx context.Context) (OperationResult, error) {
	if coordinator == nil {
		return OperationResult{}, errors.New("operations: nil coordinator")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.journal == nil {
		return OperationResult{}, ErrNoCommand
	}
	journal := coordinator.journal
	if journal.Result != nil && (journal.Phase == PhaseExecuted || journal.Phase == PhaseResultAccepted) {
		return *cloneResult(journal.Result), nil
	}
	if coordinator.pendingResult != nil {
		return coordinator.commitPendingResultLocked()
	}
	if journal.Phase != PhaseAccepted {
		return OperationResult{}, ErrCommandNotReady
	}
	started := *journal
	started.Phase = PhaseExecutionStarted
	started.Result = nil
	if err := coordinator.persistLocked(&started); err != nil {
		return OperationResult{}, err
	}
	coordinator.journal = &started
	var result OperationResult
	if err := journal.Command.Validate(coordinator.clock()); err != nil {
		category := ErrorInvalidCommand
		if commandExpiredAt(journal.Command, coordinator.clock()) {
			category = ErrorCommandExpired
		}
		result = interruptedResult(coordinator.clock, journal.Command.CommandType, category)
	} else {
		result = coordinator.executor.Execute(ctx, journal.Command.CommandType)
	}
	if resultErr := result.Validate(); resultErr != nil || result.CommandType != journal.Command.CommandType {
		category := ErrorExecutionInvalidResult
		result = interruptedResult(coordinator.clock, journal.Command.CommandType, category)
	}
	coordinator.pendingResult = cloneResult(&result)
	return coordinator.commitPendingResultLocked()
}

// Keep the journal at its durable phase until the completed result is saved.
func (coordinator *Coordinator) commitPendingResultLocked() (OperationResult, error) {
	executed := *coordinator.journal
	executed.Phase = PhaseExecuted
	executed.Result = coordinator.pendingResult
	if err := coordinator.persistLocked(&executed); err != nil {
		return OperationResult{}, err
	}
	coordinator.journal = &executed
	coordinator.pendingResult = nil
	return *cloneResult(executed.Result), nil
}

func (coordinator *Coordinator) GetResult() (OperationResult, bool, error) {
	if coordinator == nil {
		return OperationResult{}, false, errors.New("operations: nil coordinator")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.journal == nil {
		return OperationResult{}, false, nil
	}
	if coordinator.journal.Result == nil || (coordinator.journal.Phase != PhaseExecuted && coordinator.journal.Phase != PhaseResultAccepted) {
		return OperationResult{}, false, nil
	}
	return *cloneResult(coordinator.journal.Result), true, nil
}

func (coordinator *Coordinator) Acknowledge(commandID string) error {
	if coordinator == nil {
		return errors.New("operations: nil coordinator")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !validCommandID(commandID) {
		return ErrCommandNotFound
	}
	if coordinator.journal == nil || coordinator.journal.Command.CommandID != commandID {
		return ErrCommandNotFound
	}
	if coordinator.journal.Phase == PhaseResultAccepted {
		return nil
	}
	if coordinator.journal.Phase != PhaseExecuted || coordinator.journal.Result == nil {
		return ErrNoResult
	}
	acknowledged := *coordinator.journal
	acknowledged.Phase = PhaseResultAccepted
	if err := coordinator.persistLocked(&acknowledged); err != nil {
		return err
	}
	coordinator.journal = &acknowledged
	return nil
}

// CurrentCommand returns the durable command identity, when present. It is
// intentionally read-only so reconnect handling can replay an unacknowledged
// result before accepting a newer server command.
func (coordinator *Coordinator) CurrentCommand() (Command, JournalPhase, bool, error) {
	if coordinator == nil {
		return Command{}, "", false, errors.New("operations: nil coordinator")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.journal == nil {
		return Command{}, "", false, nil
	}
	return coordinator.journal.Command, coordinator.journal.Phase, true, nil
}

func (coordinator *Coordinator) recoverInterruptedLocked(journal *operationJournal) error {
	result := interruptedResult(coordinator.clock, journal.Command.CommandType, ErrorExecutionInterrupted)
	recovered := *journal
	recovered.Phase = PhaseExecuted
	recovered.Result = &result
	if err := coordinator.persistLocked(&recovered); err != nil {
		return err
	}
	coordinator.journal = &recovered
	return nil
}

func interruptedResult(clock func() time.Time, commandType CommandType, category ErrorCategory) OperationResult {
	observed := time.Now().UTC().Format(time.RFC3339Nano)
	if clock != nil {
		observed = clock().UTC().Format(time.RFC3339Nano)
	}
	result := OperationResult{Version: OperationVersion, Type: OperationType, CommandType: commandType, Result: ResultFailed, ObservedAt: observed}
	result.ErrorCategory = errorCategoryPointer(category)
	return result
}

func validateStateDirectory(stateDir string) error {
	info, err := os.Lstat(stateDir)
	if err != nil {
		return fmt.Errorf("operations: inspect state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("operations: state directory has unsafe type or permissions")
	}
	return nil
}

func loadOperationJournal(journalPath string, now time.Time) (*operationJournal, error) {
	info, err := os.Lstat(journalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("operations: inspect operation journal")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("operations: operation journal has unsafe type or permissions")
	}
	data, err := os.ReadFile(journalPath)
	if err != nil || len(data) > MaxOperationJournalBytes {
		return nil, errors.New("operations: operation journal is unreadable or oversized")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var journal operationJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, errors.New("operations: operation journal is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("operations: operation journal is malformed")
	}
	if err := validateOperationJournal(journal, now); err != nil {
		return nil, err
	}
	return &journal, nil
}

func validateOperationJournal(journal operationJournal, now time.Time) error {
	if journal.Version != OperationJournalVersion || journal.Type != OperationJournalType {
		return errors.New("operations: unsupported operation journal")
	}
	if journal.Phase != PhaseAccepted && journal.Phase != PhaseExecutionStarted && journal.Phase != PhaseExecuted && journal.Phase != PhaseResultAccepted {
		return errors.New("operations: invalid operation journal phase")
	}
	if err := journal.Command.ValidateForReplay(now); err != nil {
		return errors.New("operations: invalid operation journal command")
	}
	if journal.Phase == PhaseAccepted || journal.Phase == PhaseExecutionStarted {
		if journal.Result != nil {
			return errors.New("operations: premature operation journal result")
		}
	} else {
		if journal.Result == nil || journal.Result.Validate() != nil || journal.Result.CommandType != journal.Command.CommandType {
			return errors.New("operations: invalid operation journal result")
		}
	}
	return nil
}

func commandExpiredAt(command Command, now time.Time) bool {
	_, expires, err := command.canonicalTimes()
	return err == nil && !expires.After(now)
}

func commandStructurallyValid(command Command) bool {
	if command.Version != CommandVersion || command.Type != CommandMessageType || !validCommandID(command.CommandID) || !validCommandType(command.CommandType) || !validPayloadHash(command.PayloadHash) {
		return false
	}
	issued, expires, err := command.canonicalTimes()
	if err != nil || !expires.After(issued) || expires.Sub(issued) > MaxCommandLifetime {
		return false
	}
	expected, err := command.CanonicalPayloadHash()
	return err == nil && expected == command.PayloadHash
}

func cloneResult(result *OperationResult) *OperationResult {
	if result == nil {
		return nil
	}
	cloned := *result
	if result.ErrorCategory != nil {
		category := *result.ErrorCategory
		cloned.ErrorCategory = &category
	}
	return &cloned
}

func (coordinator *Coordinator) persistLocked(journal *operationJournal) error {
	if err := validateOperationJournalForWrite(journal); err != nil {
		return err
	}
	data, err := json.Marshal(journal)
	if err != nil || len(data) > MaxOperationJournalBytes {
		return errors.New("operations: operation journal exceeds bound")
	}
	info, statErr := os.Lstat(coordinator.journalPath)
	if statErr == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600) {
		return errors.New("operations: operation journal has unsafe replacement target")
	}
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return errors.New("operations: inspect operation journal replacement target")
	}
	temporary, err := os.CreateTemp(coordinator.stateDir, ".operation-command-*.tmp")
	if err != nil {
		return errors.New("operations: create operation journal temporary")
	}
	temporaryName := temporary.Name()
	keepTemporary := false
	defer func() {
		if !keepTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("operations: protect operation journal temporary")
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return errors.New("operations: write operation journal temporary")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("operations: sync operation journal temporary")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("operations: close operation journal temporary")
	}
	if err := os.Rename(temporaryName, coordinator.journalPath); err != nil {
		return errors.New("operations: replace operation journal")
	}
	keepTemporary = true
	directory, err := os.Open(coordinator.stateDir)
	if err != nil {
		return errors.New("operations: open state directory for sync")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("operations: sync state directory")
	}
	return nil
}

func validateOperationJournalForWrite(journal *operationJournal) error {
	if journal == nil {
		return errors.New("operations: invalid operation journal")
	}
	if journal.Version != OperationJournalVersion || journal.Type != OperationJournalType {
		return errors.New("operations: invalid operation journal")
	}
	if !commandStructurallyValid(journal.Command) {
		return errors.New("operations: invalid operation journal command")
	}
	if journal.Phase == PhaseAccepted || journal.Phase == PhaseExecutionStarted {
		if journal.Result != nil {
			return errors.New("operations: invalid operation journal result")
		}
		return nil
	}
	if journal.Phase != PhaseExecuted && journal.Phase != PhaseResultAccepted {
		return errors.New("operations: invalid operation journal phase")
	}
	if journal.Result == nil || journal.Result.CommandType != journal.Command.CommandType {
		return errors.New("operations: invalid operation journal result")
	}
	if err := journal.Result.Validate(); err != nil {
		return errors.New("operations: invalid operation journal result")
	}
	return nil
}

// RequireResolvedForRotation reads the journal without constructing an executor
// or recovering/executing an interrupted operation. Rotation cannot discard an
// operation whose outcome has not been accepted by the control plane.
func RequireResolvedForRotation(stateDir string, now time.Time) error {
	if err := validateStateDirectory(stateDir); err != nil {
		return err
	}
	if err := RequireResolvedFleetUpdate(stateDir, now); err != nil {
		return err
	}
	journal, err := loadOperationJournal(OperationJournalPath(stateDir), now)
	if err != nil {
		return err
	}
	if journal != nil && journal.Phase != PhaseResultAccepted {
		return errors.New("resolve the outstanding operation through normal agent service before rotating identity")
	}
	return nil
}

// ValidateResolvedJournal validates descriptor-read migration data without
// touching a path or performing interrupted-command recovery.
func ValidateResolvedJournal(data []byte, now time.Time) error {
	if len(data) > MaxOperationJournalBytes {
		return errors.New("operation journal exceeds limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var journal operationJournal
	if decoder.Decode(&journal) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid operation journal")
	}
	if err := validateOperationJournal(journal, now); err != nil {
		return err
	}
	if journal.Phase != PhaseResultAccepted {
		return errors.New("resolve the outstanding operation before migrating identity")
	}
	return nil
}
