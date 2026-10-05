package enrollment

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/novakiosk/agent/operations"
)

const stateFilename = "state.json"
const attemptFilename = "pending-attempt.json"

var ErrUnconfigured = errors.New("agent is unconfigured")

func StatePath(stateDir string) string {
	return filepath.Join(stateDir, stateFilename)
}

func attemptPath(stateDir string) string {
	return filepath.Join(stateDir, attemptFilename)
}

// readSecureFile requires a regular file with private (0600) permissions.
func readSecureFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("secure state file has unsafe type or permissions")
	}
	return os.ReadFile(path)
}

func LoadState(stateDir string) (State, error) {
	if strings.TrimSpace(stateDir) == "" {
		return State{}, fmt.Errorf("state directory is required")
	}
	data, err := readSecureFile(StatePath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, ErrUnconfigured
	}
	if err != nil {
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("read agent state: malformed state")
	}
	if err := normalizeState(&state); err != nil {
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	return state, nil
}

func SaveStateAtomic(stateDir string, state State) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := normalizeState(&state); err != nil {
		return fmt.Errorf("refusing to persist agent state: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	return saveAtomic(stateDir, StatePath(stateDir), data)
}

func normalizeState(state *State) error {
	if state.Version != ProtocolVersion || (state.Status != "Pending" && state.Status != "Managed") || state.InstanceURL == "" || state.EnrollmentID == "" {
		return fmt.Errorf("unsupported state")
	}
	if err := ValidateDeviceID(state.DeviceID); err != nil {
		return fmt.Errorf("invalid device ID: %w", err)
	}
	canonicalInstance, err := CanonicalInstanceURL(state.InstanceURL)
	if err != nil {
		return fmt.Errorf("unsupported instance origin")
	}
	state.InstanceURL = canonicalInstance
	if err := ValidateDeviceKind(state.DeviceKind); err != nil {
		return fmt.Errorf("invalid device kind")
	}
	state.DeviceKind = EffectiveDeviceKind(state.DeviceKind)
	if err := validatePrinterReconcileState(*state); err != nil {
		return fmt.Errorf("invalid printer reconcile evidence")
	}
	if err := validatePrinterStatisticsState(*state); err != nil {
		return fmt.Errorf("invalid printer statistics evidence")
	}
	if err := validateIdleState(*state); err != nil {
		return fmt.Errorf("invalid idle evidence")
	}
	if err := validateBrowserCommandState(*state); err != nil {
		return fmt.Errorf("invalid browser command evidence")
	}
	if state.Status == "Managed" && (state.PublicIdentityRef == "" || state.IdentityBindingID == "" || state.SessionID == "" || state.HeartbeatSequence == 0 || state.LastHeartbeatAt == "") {
		return fmt.Errorf("incomplete managed state")
	}
	return nil
}

func validatePrinterReconcileState(state State) error {
	if state.PrinterQueuesAppliedHash != "" && (state.PrinterQueuesApplyPending != nil && *state.PrinterQueuesApplyPending || state.PrinterDesiredHash == "" || len(state.PrinterQueuesAppliedHash) != 64 || strings.Trim(state.PrinterQueuesAppliedHash, "0123456789abcdef") != "") {
		return errors.New("invalid printer queues applied hash")
	}
	if state.PrinterDesiredHash == "" {
		if state.PrinterAckSequence != 0 || state.LastPrinterReconcileResult != "" || state.LastPrinterReconcileError != "" || state.LastPrinterReconcileAt != "" || state.LastPrinterReconcileAccepted {
			return errors.New("incomplete printer reconcile evidence")
		}
		return nil
	}
	if len(state.PrinterDesiredHash) != 64 || strings.Trim(state.PrinterDesiredHash, "0123456789abcdef") != "" || state.PrinterAckSequence == 0 || !validPrinterReconcileResult(state.LastPrinterReconcileResult, state.LastPrinterReconcileError) {
		return errors.New("invalid printer reconcile evidence")
	}
	if observed, err := time.Parse(time.RFC3339Nano, state.LastPrinterReconcileAt); err != nil || observed.IsZero() {
		return errors.New("invalid printer reconcile timestamp")
	}
	return nil
}

func validateIdleState(state State) error {
	empty := state.LastIdleScreenID == "" && state.LastIdleRevisionID == "" && state.LastIdlePayloadHash == "" && state.LastIdleAckResult == "" && state.LastIdleAckError == "" && state.LastIdleAckAt == ""
	if empty {
		if state.IdleAckSequence != 0 || state.LastIdleAckAccepted || state.LastIdleRemoved {
			return errors.New("incomplete idle evidence")
		}
		return nil
	}
	if state.IdleAckSequence == 0 || state.LastIdleScreenID == "" || state.LastIdleRevisionID == "" || len(state.LastIdlePayloadHash) != 64 || strings.Trim(state.LastIdlePayloadHash, "0123456789abcdef") != "" || (state.LastIdleAckResult != "applied" && state.LastIdleAckResult != "failed") {
		return errors.New("invalid idle evidence")
	}
	if state.LastIdleAckResult == "applied" && state.LastIdleAckError != "" {
		return errors.New("applied idle evidence has an error")
	}
	if observed, err := time.Parse(time.RFC3339Nano, state.LastIdleAckAt); err != nil || observed.IsZero() {
		return errors.New("invalid idle timestamp")
	}
	return nil
}

func validatePrinterStatisticsState(state State) error {
	if state.LastPrinterStatisticsHash == "" {
		if state.PrinterStatisticsSequence != 0 || state.LastPrinterStatisticsAttemptAt != "" || state.LastPrinterStatisticsAccepted {
			return errors.New("incomplete printer statistics evidence")
		}
		return nil
	}
	if len(state.LastPrinterStatisticsHash) != 64 || strings.Trim(state.LastPrinterStatisticsHash, "0123456789abcdef") != "" || state.PrinterStatisticsSequence == 0 {
		return errors.New("invalid printer statistics evidence")
	}
	if observed, err := time.Parse(time.RFC3339Nano, state.LastPrinterStatisticsAttemptAt); err != nil || observed.IsZero() {
		return errors.New("invalid printer statistics timestamp")
	}
	return nil
}

func validateBrowserCommandState(state State) error {
	if state.LastBrowserCommandID == "" {
		if state.BrowserCommandSequence != 0 || state.LastBrowserCommandHash != "" || state.LastBrowserCommandResult != "" || state.LastBrowserCommandError != "" || state.LastBrowserCommandObservedURL != "" || state.LastBrowserCommandZoom != nil || state.LastBrowserCommandAt != "" || state.LastBrowserCommandAccepted {
			return errors.New("incomplete browser command evidence")
		}
		return nil
	}
	if !browserCommandUUID.MatchString(state.LastBrowserCommandID) || len(state.LastBrowserCommandHash) != 64 || strings.Trim(state.LastBrowserCommandHash, "0123456789abcdef") != "" || state.BrowserCommandSequence == 0 || (state.LastBrowserCommandResult != "applied" && state.LastBrowserCommandResult != "failed") || len(state.LastBrowserCommandObservedURL) > 2048 {
		return errors.New("invalid browser command evidence")
	}
	if state.LastBrowserCommandResult == "applied" && state.LastBrowserCommandError != "" {
		return errors.New("applied browser command has an error")
	}
	if state.LastBrowserCommandResult == "failed" && !browserCommandErrors[state.LastBrowserCommandError] {
		return errors.New("browser command failure category is invalid")
	}
	if state.LastBrowserCommandZoom != nil && !BrowserZoomAllowlist[*state.LastBrowserCommandZoom] {
		return errors.New("browser command zoom is invalid")
	}
	if observed, err := parseBrowserCommandTimestamp(state.LastBrowserCommandAt); err != nil || observed.IsZero() {
		return errors.New("invalid browser command timestamp")
	}
	return nil
}

func LoadAttempt(stateDir string) (Request, error) {
	if strings.TrimSpace(stateDir) == "" {
		return Request{}, fmt.Errorf("state directory is required")
	}
	data, err := readSecureFile(attemptPath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return Request{}, ErrUnconfigured
	}
	if err != nil {
		return Request{}, fmt.Errorf("read pending enrollment attempt: %w", err)
	}
	var request Request
	if err := json.Unmarshal(data, &request); err != nil {
		return Request{}, fmt.Errorf("read pending enrollment attempt: malformed state")
	}
	if request.Version != ProtocolVersion || request.Type != "bootstrap.enrollment" || request.IdempotencyKey == "" || request.DeviceID == "" || request.Proof.Value == "" {
		return Request{}, fmt.Errorf("read pending enrollment attempt: unsupported state")
	}
	if err := ValidateDeviceID(request.DeviceID); err != nil {
		return Request{}, fmt.Errorf("read pending enrollment attempt: invalid device ID: %w", err)
	}
	if err := ValidateDeviceKind(request.DeviceKind); err != nil {
		return Request{}, fmt.Errorf("read pending enrollment attempt: invalid device kind")
	}
	return request, nil
}

func SaveAttemptAtomic(stateDir string, request Request) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	if request.Version != ProtocolVersion || request.Type != "bootstrap.enrollment" || request.IdempotencyKey == "" || request.DeviceID == "" || request.Proof.Value == "" {
		return fmt.Errorf("refusing to persist invalid enrollment attempt")
	}
	if err := ValidateDeviceKind(request.DeviceKind); err != nil {
		return fmt.Errorf("refusing to persist invalid device kind")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}
	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment attempt: %w", err)
	}
	return saveAtomic(stateDir, attemptPath(stateDir), data)
}

func ClearAttempt(stateDir string) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := os.Remove(attemptPath(stateDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear pending enrollment attempt")
	}
	return nil
}

// Reset clears only local enrollment authority. The identity file is checked
// before anything is removed and is never rewritten, so a reset preserves the
// device key and opaque device ID for a subsequent attended enrollment.
func Reset(stateDir string) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	directoryInfo, err := os.Lstat(stateDir)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm() != 0o700 {
		return fmt.Errorf("state directory has unsafe type or permissions")
	}
	if _, err := LoadIdentityForReset(stateDir); err != nil {
		return err
	}

	// Validate every target before removing any artifact. Remove the journal
	// before enrollment state so a partial reset cannot authorize old commands
	// under a new enrollment. Lstat makes symlinks,
	// directories, devices, and unsafe modes fail closed; absent files are
	// intentionally harmless.
	for _, path := range []string{operations.OperationJournalPath(stateDir), attemptPath(stateDir), StatePath(stateDir)} {
		info, statErr := os.Lstat(path)
		if errors.Is(statErr, fs.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return fmt.Errorf("inspect reset artifact: %w", statErr)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("reset artifact has unsafe type or permissions")
		}
	}
	for _, path := range []string{operations.OperationJournalPath(stateDir), attemptPath(stateDir), StatePath(stateDir)} {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return fmt.Errorf("clear reset artifact: %w", removeErr)
		}
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

// LoadIdentityForReset validates and reads the identity without performing the
// legacy migration that LoadIdentity may perform. Reset must never rewrite the
// identity as a side effect of displaying its device ID.
func LoadIdentityForReset(stateDir string) (Identity, error) { return InspectIdentity(stateDir) }

func saveAtomic(stateDir, destination string, data []byte) error {
	temporary, err := os.CreateTemp(stateDir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create state temporary: %w", err)
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
		return fmt.Errorf("protect state temporary: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write agent state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync agent state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close agent state: %w", err)
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("commit agent state: %w", err)
	}
	keepTemporary = true
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return os.Chmod(destination, 0o600)
}
