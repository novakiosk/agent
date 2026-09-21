package operations

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var commandTestNow = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func testCommand(t *testing.T, id string, kind CommandType, issued, expires time.Time) Command {
	t.Helper()
	command := Command{
		Version: CommandVersion, Type: CommandMessageType, CommandID: id,
		CommandType: kind, IssuedAt: issued.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano),
	}
	hash, err := command.CanonicalPayloadHash()
	if err != nil {
		t.Fatalf("command hash: %v", err)
	}
	command.PayloadHash = hash
	return command
}

func validTestCommand(t *testing.T, id string) Command {
	return testCommand(t, id, CommandReboot, commandTestNow.Add(-time.Minute), commandTestNow.Add(20*time.Minute))
}

func TestCommandCanonicalHashAndStrictValidation(t *testing.T) {
	command := validTestCommand(t, "11111111-1111-4111-8111-111111111111")
	if err := command.Validate(commandTestNow); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	payload, err := command.CanonicalPayload()
	if err != nil || !strings.HasPrefix(string(payload), "operation-command-canonical-v1\n") {
		t.Fatalf("canonical payload = %q err=%v", payload, err)
	}
	hashA, err := command.CanonicalPayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	if hashA != command.PayloadHash || len(hashA) != 64 {
		t.Fatalf("unexpected command hash: %q", hashA)
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Command
	err = json.Unmarshal(encoded, &decoded)
	if err != nil || !SameCommand(decoded, command) {
		t.Fatalf("decoded = %#v err=%v", decoded, err)
	}
	withUnknown := strings.TrimSuffix(string(encoded), "}") + `,"argv":["reboot"]}`
	if err := json.Unmarshal([]byte(withUnknown), &decoded); err == nil {
		t.Fatal("command decoder accepted arbitrary argv")
	}
	uppercaseID := command
	uppercaseID.CommandID = "11111111-1111-4111-8111-11111111111A"
	if err := uppercaseID.Validate(commandTestNow); err == nil {
		t.Fatal("Validate accepted uppercase command ID")
	}
	for _, expired := range []Command{
		testCommand(t, command.CommandID, CommandReboot, commandTestNow.Add(-2*time.Hour), commandTestNow.Add(-time.Minute)),
		testCommand(t, "22222222-2222-4222-8222-222222222222", CommandPoweroff, commandTestNow.Add(3*time.Minute), commandTestNow.Add(10*time.Minute)),
	} {
		if err := expired.Validate(commandTestNow); err == nil {
			t.Fatal("Validate accepted expired/future command")
		}
	}
	tooLong := testCommand(t, "33333333-3333-4333-8333-333333333333", CommandSystemUpdate, commandTestNow, commandTestNow.Add(MaxCommandLifetime+time.Second))
	if err := tooLong.Validate(commandTestNow); err == nil {
		t.Fatal("Validate accepted command lifetime over one hour")
	}
}

func TestSameCommandComparesEveryClosedField(t *testing.T) {
	command := validTestCommand(t, "88888888-8888-4888-8888-888888888888")
	mutations := []func(*Command){
		func(value *Command) { value.Version++ },
		func(value *Command) { value.Type = "operation.command.changed" },
		func(value *Command) { value.CommandID = "99999999-9999-4999-8999-999999999999" },
		func(value *Command) { value.CommandType = CommandPoweroff },
		func(value *Command) { value.IssuedAt = "2026-08-24T11:58:00Z" },
		func(value *Command) { value.ExpiresAt = "2026-08-24T12:30:00Z" },
		func(value *Command) { value.PayloadHash = strings.Repeat("a", 64) },
	}
	for index, mutate := range mutations {
		changed := command
		mutate(&changed)
		if SameCommand(command, changed) {
			t.Fatalf("mutation %d was treated as the same command: %#v", index, changed)
		}
	}
}

type countingExecutor struct {
	calls  int
	result OperationResult
}

func (executor *countingExecutor) Execute(_ context.Context, commandType CommandType) OperationResult {
	executor.calls++
	result := executor.result
	result.CommandType = commandType
	return result
}

func newCountingExecutor() *countingExecutor {
	return &countingExecutor{result: OperationResult{
		Version: OperationVersion, Type: OperationType, Result: ResultScheduled,
		ObservedAt: commandTestNow.Format(time.RFC3339Nano), BootIDBefore: "00112233-4455-6677-8899-aabbccddeeff",
	}}
}

func newCoordinator(t *testing.T, executor CommandExecutor, stateDir string) *Coordinator {
	t.Helper()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: executor, Clock: func() time.Time { return commandTestNow }})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	return coordinator
}

func TestCoordinatorDuplicateConflictBusyReplayAndAcknowledge(t *testing.T) {
	stateDir := t.TempDir()
	executor := newCountingExecutor()
	coordinator := newCoordinator(t, executor, stateDir)
	first := validTestCommand(t, "11111111-1111-4111-8111-111111111111")
	accepted, err := coordinator.Accept(first)
	if err != nil || accepted.Status != AcceptanceAccepted || accepted.Phase != PhaseAccepted {
		t.Fatalf("accepted = %#v err=%v", accepted, err)
	}
	duplicate, err := coordinator.Accept(first)
	if err != nil || duplicate.Status != AcceptanceDuplicate {
		t.Fatalf("duplicate = %#v err=%v", duplicate, err)
	}
	changed := testCommand(t, first.CommandID, CommandReboot, firstIssued(first).Add(-30*time.Second), commandTestNow.Add(20*time.Minute))
	if _, err := coordinator.Accept(changed); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed command error = %v", err)
	}
	different := validTestCommand(t, "22222222-2222-4222-8222-222222222222")
	if _, err := coordinator.Accept(different); !errors.Is(err, ErrCommandBusy) {
		t.Fatalf("busy command error = %v", err)
	}
	result, err := coordinator.ExecuteOnce(context.Background())
	if err != nil || result.Result != ResultScheduled || executor.calls != 1 {
		t.Fatalf("execute result=%#v err=%v calls=%d", result, err, executor.calls)
	}
	replayed, err := coordinator.ExecuteOnce(context.Background())
	if err != nil || replayed.Result != ResultScheduled || executor.calls != 1 {
		t.Fatalf("replay result=%#v err=%v calls=%d", replayed, err, executor.calls)
	}
	if err := coordinator.Acknowledge(first.CommandID); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Acknowledge(first.CommandID); err != nil {
		t.Fatalf("idempotent acknowledge: %v", err)
	}
	acceptedNext, err := coordinator.Accept(different)
	if err != nil || acceptedNext.Status != AcceptanceAccepted {
		t.Fatalf("next accept = %#v err=%v", acceptedNext, err)
	}
	if _, err := coordinator.ExecuteOnce(context.Background()); err != nil || executor.calls != 2 {
		t.Fatalf("next execute err=%v calls=%d", err, executor.calls)
	}
}

func TestCoordinatorExpiredExactDuplicateStillConverges(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	executor := newCountingExecutor()
	clock := commandTestNow
	coordinator, err := NewCoordinator(CoordinatorConfig{
		StateDir: stateDir,
		Executor: executor,
		Clock:    func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	command := validTestCommand(t, "66666666-6666-4666-8666-666666666666")
	if _, err := coordinator.Accept(command); err != nil {
		t.Fatal(err)
	}
	clock = commandTestNow.Add(30 * time.Minute)
	duplicate, err := coordinator.Accept(command)
	if err != nil || duplicate.Status != AcceptanceDuplicate || duplicate.Phase != PhaseAccepted {
		t.Fatalf("expired duplicate = %#v err=%v", duplicate, err)
	}
}

func TestCommandReplayValidationAllowsOnlyAlreadyJournaledExpiry(t *testing.T) {
	command := testCommand(t, "01234567-89ab-cdef-0123-456789abcdef", CommandSystemUpdate, commandTestNow, commandTestNow.Add(time.Minute))
	if err := command.Validate(commandTestNow); err != nil {
		t.Fatal(err)
	}
	if err := command.ValidateForReplay(commandTestNow.Add(2 * time.Minute)); err != nil {
		t.Fatalf("accepted command replay validation failed: %v", err)
	}
	future := command
	future.IssuedAt = commandTestNow.Add(3 * time.Minute).Format(time.RFC3339)
	future.ExpiresAt = commandTestNow.Add(4 * time.Minute).Format(time.RFC3339)
	future.PayloadHash, _ = future.CanonicalPayloadHash()
	if err := future.ValidateForReplay(commandTestNow); err == nil {
		t.Fatal("future unjournaled command unexpectedly passed replay validation")
	}
}

type wrongTypeExecutor struct{}

func (wrongTypeExecutor) Execute(context.Context, CommandType) OperationResult {
	return OperationResult{
		Version: OperationVersion, Type: OperationType, CommandType: CommandPoweroff,
		Result: ResultScheduled, ObservedAt: commandTestNow.Format(time.RFC3339Nano),
	}
}

func TestCoordinatorRejectsExecutorResultForWrongCommandType(t *testing.T) {
	stateDir := t.TempDir()
	coordinator := newCoordinator(t, wrongTypeExecutor{}, stateDir)
	command := validTestCommand(t, "77777777-7777-4777-8777-777777777777")
	if _, err := coordinator.Accept(command); err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ExecuteOnce(context.Background())
	if err != nil || result.Result != ResultFailed || result.ErrorCategory == nil || *result.ErrorCategory != ErrorExecutionInvalidResult {
		t.Fatalf("wrong-type result=%#v err=%v", result, err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: wrongTypeExecutor{}, Clock: func() time.Time { return commandTestNow }}); err != nil {
		t.Fatalf("reload wrong-type result: %v", err)
	}
}

func firstIssued(command Command) time.Time {
	parsed, _ := parseCanonicalUTCTimestamp(command.IssuedAt)
	return parsed
}

func TestCoordinatorRecoversInterruptedExecutionWithoutReexecution(t *testing.T) {
	stateDir := t.TempDir()
	command := validTestCommand(t, "44444444-4444-4444-8444-444444444444")
	executor := newCountingExecutor()
	coordinator := newCoordinator(t, executor, stateDir)
	if _, err := coordinator.Accept(command); err != nil {
		t.Fatal(err)
	}
	// ExecuteOnce is the only path that invokes the executor; an on-disk
	// execution_started record represents a crash immediately before it.
	journal := operationJournal{Version: OperationJournalVersion, Type: OperationJournalType, Phase: PhaseExecutionStarted, Command: command}
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(OperationJournalPath(stateDir), data, 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: executor, Clock: func() time.Time { return commandTestNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	result, present, err := recovered.GetResult()
	if err != nil || !present || result.Result != ResultFailed || result.ErrorCategory == nil || *result.ErrorCategory != ErrorExecutionInterrupted {
		t.Fatalf("recovered result=%#v err=%v", result, err)
	}
	if executor.calls != 0 {
		t.Fatalf("recovery invoked executor %d times", executor.calls)
	}
	if _, err := recovered.ExecuteOnce(context.Background()); err != nil || executor.calls != 0 {
		t.Fatalf("recovery replay err=%v calls=%d", err, executor.calls)
	}
	_, phase, present, err := recovered.CurrentCommand()
	if err != nil || !present || phase != PhaseExecuted {
		t.Fatalf("phase=%q err=%v", phase, err)
	}
}

func TestCoordinatorJournalSafetyAndParentMode(t *testing.T) {
	parent := t.TempDir()
	stateDir := filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	executor := newCountingExecutor()
	coordinator := newCoordinator(t, executor, stateDir)
	command := validTestCommand(t, "55555555-5555-4555-8555-555555555555")
	if _, err := coordinator.Accept(command); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("parent mode changed: %v %v", info, err)
	}
	journalInfo, err := os.Stat(OperationJournalPath(stateDir))
	if err != nil || journalInfo.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode=%v err=%v", journalInfo.Mode().Perm(), err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: executor, Clock: func() time.Time { return commandTestNow }}); err != nil {
		t.Fatalf("reload error = %v", err)
	}
	if err := os.Chmod(OperationJournalPath(stateDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: executor}); err == nil {
		t.Fatal("accepted unsafe journal mode")
	}
	if err := os.Remove(OperationJournalPath(stateDir)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "journal-target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, OperationJournalPath(stateDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: executor}); err == nil {
		t.Fatal("accepted journal symlink")
	}
	unsafeState := filepath.Join(parent, "unsafe-state")
	if err := os.Mkdir(unsafeState, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: unsafeState, Executor: executor}); err == nil {
		t.Fatal("accepted unsafe state directory mode")
	}
	stateLink := filepath.Join(parent, "state-link")
	if err := os.Symlink(stateDir, stateLink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: stateLink, Executor: executor}); err == nil {
		t.Fatal("accepted symlink state directory")
	}
}

func TestCoordinatorCorruptedAndOversizedJournalFailClosed(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := OperationJournalPath(stateDir)
	if err := os.WriteFile(path, []byte(`{"version":1,"type":"operation.journal","phase":"accepted"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(CoordinatorConfig{StateDir: stateDir, Executor: newCountingExecutor()}); err == nil {
		t.Fatal("accepted malformed journal")
	}
	journal := operationJournal{Version: OperationJournalVersion, Type: OperationJournalType, Phase: PhaseAccepted, Command: validTestCommand(t, "11111111-1111-4111-8111-111111111111")}
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config := CoordinatorConfig{StateDir: stateDir, Executor: newCountingExecutor(), Clock: func() time.Time { return commandTestNow }}
	if _, err := NewCoordinator(config); err != nil {
		t.Fatalf("valid journal fixture rejected: %v", err)
	}
	// JSON whitespace keeps the journal valid while crossing only the byte bound.
	data = append(data, []byte(strings.Repeat(" ", MaxOperationJournalBytes-len(data)+1))...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(config); err == nil {
		t.Fatal("accepted oversized journal")
	}
}

type resultCommitFailureExecutor struct {
	*countingExecutor
	journalPath string
	t           *testing.T
}

func (executor *resultCommitFailureExecutor) Execute(ctx context.Context, kind CommandType) OperationResult {
	result := executor.countingExecutor.Execute(ctx, kind)
	// A real unsafe replacement target prevents the final journal write even
	// when tests run as root; restoring its mode restores persistence.
	if err := os.Chmod(executor.journalPath, 0400); err != nil {
		executor.t.Fatal(err)
	}
	return result
}

func TestCoordinatorRetriesCompletedResultCommitWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	executor := &resultCommitFailureExecutor{countingExecutor: newCountingExecutor(), journalPath: OperationJournalPath(dir), t: t}
	coordinator := newCoordinator(t, executor, dir)
	command := validTestCommand(t, "11111111-1111-4111-8111-111111111111")
	next := validTestCommand(t, "22222222-2222-4222-8222-222222222222")
	if _, err := coordinator.Accept(command); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := coordinator.ExecuteOnce(context.Background()); err == nil {
			t.Fatal("unsafe journal replacement unexpectedly succeeded")
		}
		if executor.calls != 1 {
			t.Fatalf("executor called %d times", executor.calls)
		}
		if _, present, err := coordinator.GetResult(); err != nil || present {
			t.Fatal("undurable result exposed")
		}
		acceptance, err := coordinator.Accept(command)
		if err != nil || acceptance.Phase != PhaseExecutionStarted || acceptance.Result != nil {
			t.Fatal("duplicate exposed undurable result")
		}
		if _, err := coordinator.Accept(next); !errors.Is(err, ErrCommandBusy) {
			t.Fatalf("new command admitted: %v", err)
		}
		if err := coordinator.Acknowledge(command.CommandID); !errors.Is(err, ErrNoResult) {
			t.Fatalf("undurable result acknowledged: %v", err)
		}
	}
	if err := os.Chmod(executor.journalPath, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ExecuteOnce(context.Background())
	want := executor.result
	want.CommandType = command.CommandType
	if err != nil || !reflect.DeepEqual(result, want) || executor.calls != 1 {
		t.Fatalf("commit recovery result=%+v error=%v calls=%d", result, err, executor.calls)
	}
	journal, err := loadOperationJournal(executor.journalPath, commandTestNow)
	if err != nil || journal.Phase != PhaseExecuted || !reflect.DeepEqual(journal.Result, &want) {
		t.Fatalf("result not durable: %+v %v", journal, err)
	}
	if replay, present, err := coordinator.GetResult(); err != nil || !present || !reflect.DeepEqual(replay, want) {
		t.Fatal("exact result replay failed")
	}
	if err := coordinator.Acknowledge(command.CommandID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Accept(next); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ExecuteOnce(context.Background()); err == nil || executor.calls != 2 {
		t.Fatalf("new command did not execute independently: %v %d", err, executor.calls)
	}
}

func TestCoordinatorFailedStartedCommitNeverExecutes(t *testing.T) {
	dir := t.TempDir()
	executor := newCountingExecutor()
	coordinator := newCoordinator(t, executor, dir)
	if _, err := coordinator.Accept(validTestCommand(t, "11111111-1111-4111-8111-111111111111")); err != nil {
		t.Fatal(err)
	}
	path := OperationJournalPath(dir)
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ExecuteOnce(context.Background()); err == nil || executor.calls != 0 {
		t.Fatal("executed without durable start")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ExecuteOnce(context.Background()); err != nil || executor.calls != 1 {
		t.Fatalf("start retry failed: %v", err)
	}
}
