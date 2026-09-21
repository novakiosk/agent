package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	runtimeCommandOutputLimit = 32 * 1024
	runtimeDiagnosticLimit    = 2 * 1024
	runtimeManifestName       = ".novakiosk-agent-runtime-manifest.json"
)

var (
	runtimeURLPattern    = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	swayErrorLinePattern = regexp.MustCompile(`(?i)^\s*error\s+on\s+line\s+[0-9]+\s+`)
)

// ErrRuntimeTransactionInterrupted is a test/integration seam representing a
// process stop at a transaction boundary. The applier deliberately leaves its
// journal in place for recovery when this error is returned.
var ErrRuntimeTransactionInterrupted = errors.New("runtime transaction interrupted")

// RuntimeTransactionHook is invoked at bounded transaction boundaries. It is
// intentionally not a general filesystem hook: production leaves it nil, and
// tests use it only to model an interruption at a named replacement boundary.
type RuntimeTransactionHook func(string) error

type RuntimeCommandRunner interface {
	Run(context.Context, string, []string, []string) ([]byte, error)
}

type ExecRuntimeCommandRunner struct{}

type runtimeCommandError struct {
	command    string
	diagnostic string
	cause      error
}

func (err *runtimeCommandError) Error() string {
	name := filepath.Base(err.command)
	if err.diagnostic == "" {
		return fmt.Sprintf("runtime command %s failed: %v", name, err.cause)
	}
	return fmt.Sprintf("runtime command %s failed: %s", name, err.diagnostic)
}

func (err *runtimeCommandError) Unwrap() error { return err.cause }

func (err *runtimeCommandError) Diagnostic() string { return err.diagnostic }

func sanitizeRuntimeDiagnostic(data []byte) string {
	data = []byte(redactRuntimeDiagnostic(string(data)))
	var output strings.Builder
	truncated := false
	const truncationMarker = "…"
	for _, character := range string(data) {
		encoded := string(character)
		switch character {
		case '\n':
			encoded = `\n`
		case '\r':
			encoded = `\r`
		case '\t':
			encoded = `\t`
		default:
			if unicode.IsControl(character) {
				encoded = fmt.Sprintf(`\x%02x`, character)
			}
		}
		// Reserve room for the marker so the returned diagnostic remains within
		// the advertised bound even after truncation.
		if output.Len()+len(encoded) > runtimeDiagnosticLimit-len(truncationMarker) {
			truncated = true
			break
		}
		output.WriteString(encoded)
	}
	if truncated {
		output.WriteString(truncationMarker)
	}
	return output.String()
}

func redactRuntimeDiagnostic(text string) string {
	// Sway may include the complete value of an invalid config line in an
	// "Error on line ..." message. Redact that known echo form while retaining
	// the line number and parser reason. URL redaction applies to ordinary
	// validator output as well, since a URL is configuration data, not a useful
	// local failure cause.
	text = runtimeURLPattern.ReplaceAllString(text, "[redacted-url]")
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		if redacted, ok := redactSwayErrorLine(line); ok {
			lines[index] = redacted
		}
	}
	return strings.Join(lines, "\n")
}

func redactSwayErrorLine(line string) (string, bool) {
	match := swayErrorLinePattern.FindStringIndex(line)
	if match == nil {
		return line, false
	}
	prefix := line[:match[1]]
	rest := line[match[1]:]
	if len(rest) < 3 || (rest[0] != '\'' && rest[0] != '"') {
		return line, false
	}
	quote := rest[0]
	for index := 1; index < len(rest); index++ {
		if rest[index] != quote {
			continue
		}
		remainder := strings.TrimLeft(rest[index+1:], " \t")
		if !strings.HasPrefix(remainder, ":") {
			continue
		}
		reason := strings.TrimSpace(strings.TrimPrefix(remainder, ":"))
		return prefix + "[redacted-config]: " + reason, true
	}
	return line, false
}

func (ExecRuntimeCommandRunner) Run(ctx context.Context, name string, args []string, environment []string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = mergeRuntimeEnvironment(os.Environ(), environment)
	var output bytes.Buffer
	limited := &limitedRuntimeWriter{writer: &output, limit: runtimeCommandOutputLimit}
	command.Stdout = limited
	command.Stderr = limited
	if err := command.Run(); err != nil {
		if limited.exceeded {
			return nil, fmt.Errorf("runtime command output exceeded limit: %w", err)
		}
		diagnostic := sanitizeRuntimeDiagnostic(output.Bytes())
		if diagnostic == "" {
			diagnostic = sanitizeRuntimeDiagnostic([]byte(err.Error()))
		}
		return output.Bytes(), &runtimeCommandError{command: name, diagnostic: diagnostic, cause: err}
	}
	if limited.exceeded {
		return nil, fmt.Errorf("runtime command output exceeded limit")
	}
	return output.Bytes(), nil
}

func mergeRuntimeEnvironment(base, overrides []string) []string {
	merged := append([]string(nil), base...)
	for _, override := range overrides {
		name, _, found := strings.Cut(override, "=")
		if !found || name == "" {
			continue
		}
		for index, m := range slices.Backward(merged) {
			if strings.HasPrefix(m, name+"=") {
				merged = append(merged[:index], merged[index+1:]...)
			}
		}
		merged = append(merged, override)
	}
	return merged
}

type limitedRuntimeWriter struct {
	writer   io.Writer
	limit    int
	exceeded bool
}

func (writer *limitedRuntimeWriter) Write(data []byte) (int, error) {
	originalLength := len(data)
	if len(data) > writer.limit {
		data = data[:writer.limit]
		writer.exceeded = true
	}
	count, err := writer.writer.Write(data)
	writer.limit -= count
	if err != nil {
		return count, err
	}
	return originalLength, nil
}

type RuntimeApplierOptions struct {
	ConfigDir       string
	CommandRunner   RuntimeCommandRunner
	SwayBinary      string
	SwayMsgBinary   string
	SwaySocket      string
	ValidateSocket  func(string) error
	NovaKeysBinary  string
	TransactionHook RuntimeTransactionHook
	// RuntimeDirPath and RuntimeDirInfo are injectable filesystem seams for
	// tests. Production derives /run/user/<uid> and verifies it with os.Lstat.
	RuntimeDirPath func(uid int) string
	RuntimeDirInfo func(path string) (os.FileInfo, error)
}

type RuntimeApplier interface {
	Recover(context.Context) error
	Apply(context.Context, RuntimeArtifact) error
}

type SwayRuntimeApplier struct {
	options    RuntimeApplierOptions
	runtimeDir string
}

func NewSwayRuntimeApplier(options RuntimeApplierOptions) (*SwayRuntimeApplier, error) {
	if options.CommandRunner == nil {
		options.CommandRunner = ExecRuntimeCommandRunner{}
	}
	if options.SwayBinary == "" {
		options.SwayBinary = "/usr/bin/sway"
	}
	if options.SwayMsgBinary == "" {
		options.SwayMsgBinary = "/usr/bin/swaymsg"
	}
	if options.NovaKeysBinary == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil || home == "" {
			return nil, fmt.Errorf("NOVA Keys home directory is unavailable")
		}
		options.NovaKeysBinary = filepath.Join(home, ".local", "bin", "novakeys")
	}
	if options.ConfigDir == "" {
		configDir, err := os.UserConfigDir()
		if err != nil || configDir == "" {
			return nil, fmt.Errorf("runtime config directory is unavailable")
		}
		options.ConfigDir = configDir
	}
	if err := validateRuntimePath(options.ConfigDir); err != nil {
		return nil, fmt.Errorf("runtime config directory: %w", err)
	}
	runtimeDir, err := safeRuntimeDir(options)
	if err != nil {
		return nil, err
	}
	return &SwayRuntimeApplier{options: options, runtimeDir: runtimeDir}, nil
}

type runtimeManagedFile struct {
	data    []byte
	present bool
}

type runtimeManifest struct {
	Version int      `json:"version"`
	Layouts []string `json:"layouts"`
}

// Recover completes an interrupted local transaction independently of desired state.
func (applier *SwayRuntimeApplier) Recover(ctx context.Context) error {
	recovery, err := recoverRuntimeTransaction(applier.options.ConfigDir)
	if err != nil {
		return fmt.Errorf("recover runtime transaction: %w", err)
	}
	if recovery.NeedsReload {
		if err := applier.finishRuntimeRecovery(ctx, recovery); err != nil {
			return fmt.Errorf("finish runtime recovery: %w", err)
		}
	}
	return nil
}

func (applier *SwayRuntimeApplier) Apply(ctx context.Context, artifact RuntimeArtifact) error {
	if err := applier.Recover(ctx); err != nil {
		return err
	}
	if err := ValidateRuntimeArtifact(artifact); err != nil {
		return fmt.Errorf("runtime artifact rejected: %w", err)
	}
	if artifact.Status != "ready" || artifact.Sway == nil || artifact.NOVAKeys == nil {
		return fmt.Errorf("runtime artifact is blocked")
	}
	if strings.Contains(artifact.Sway.Text, "{{presentation_url}}") {
		return fmt.Errorf("runtime artifact still contains presentation marker")
	}
	if artifact.Browser != nil {
		if artifact.Browser.Type != "direct-chromium-v1" {
			return fmt.Errorf("runtime browser descriptor is unsupported")
		}
		// The descriptor is only valid for the generated simple Chromium
		// configuration. A signed descriptor must not turn raw Sway into a
		// duplicate unmanaged browser session.
		if artifact.Sway.Mode != "simple" || !strings.Contains(artifact.Sway.Text, "direct-chromium-v1") {
			return fmt.Errorf("runtime browser descriptor does not match Sway configuration")
		}
	}
	if strings.Contains(artifact.Sway.Text, "exec_always --no-startup-id ~/.local/bin/novakeys") && !runtimeExecutableAvailable(applier.options.NovaKeysBinary) {
		return fmt.Errorf("NOVA Keys executable is missing or not executable")
	}
	configDir := applier.options.ConfigDir
	swayDir := filepath.Join(configDir, "sway")
	novaKeysDir := filepath.Join(configDir, "novakeys")
	for _, path := range []string{configDir, swayDir, novaKeysDir} {
		if err := ensureRuntimeDirectory(path); err != nil {
			return err
		}
	}
	manifestPath := filepath.Join(novaKeysDir, runtimeManifestName)
	manifest, err := readRuntimeManifest(manifestPath)
	if err != nil {
		return err
	}
	newLayoutCodes := make([]string, 0, len(artifact.Layouts))
	for _, layout := range artifact.Layouts {
		if !isSafeRuntimeLanguageCode(layout.LanguageCode) {
			return fmt.Errorf("runtime layout language code is unsafe")
		}
		newLayoutCodes = append(newLayoutCodes, layout.LanguageCode)
	}
	sort.Strings(newLayoutCodes)
	newLayoutSet := make(map[string]bool, len(newLayoutCodes))
	for _, code := range newLayoutCodes {
		if newLayoutSet[code] {
			return fmt.Errorf("runtime layout language code is duplicated")
		}
		newLayoutSet[code] = true
	}

	paths := []string{filepath.Join(swayDir, "config"), filepath.Join(novaKeysDir, "config"), manifestPath}
	for _, code := range manifest.Layouts {
		if !isSafeRuntimeLanguageCode(code) {
			return fmt.Errorf("runtime manifest contains unsafe layout")
		}
		paths = append(paths, filepath.Join(novaKeysDir, "layout-"+code+".toml"))
	}
	for _, code := range newLayoutCodes {
		paths = append(paths, filepath.Join(novaKeysDir, "layout-"+code+".toml"))
	}
	previous := make(map[string]runtimeManagedFile, len(paths))
	for _, path := range paths {
		file, readErr := readRuntimeManagedFile(path)
		if readErr != nil {
			return readErr
		}
		previous[path] = file
	}

	// Validation runs against the staged Sway file before any managed target is
	// replaced. The temporary file is still inside the trusted Sway directory.
	stagedSway, err := stageRuntimeFile(swayDir, []byte(artifact.Sway.Text))
	if err != nil {
		return err
	}
	defer os.Remove(stagedSway)
	if _, err := applier.run(ctx, applier.options.SwayBinary, []string{"--validate", "--config", stagedSway}, applier.runtimeValidationEnvironment()); err != nil {
		return fmt.Errorf("validate staged Sway config: %w", err)
	}

	managed := make(map[string][]byte, 2+len(artifact.Layouts))
	managed[filepath.Join(swayDir, "config")] = []byte(artifact.Sway.Text)
	managed[filepath.Join(novaKeysDir, "config")] = []byte(artifact.NOVAKeys.Text)
	for _, layout := range artifact.Layouts {
		managed[filepath.Join(novaKeysDir, "layout-"+layout.LanguageCode+".toml")] = []byte(layout.TOML)
	}
	manifestData, _ := json.Marshal(runtimeManifest{Version: 1, Layouts: newLayoutCodes})
	managed[manifestPath] = append(manifestData, '\n')
	journal, err := buildRuntimeTransactionJournal(configDir, managed, previous, artifact.ArtifactHash)
	if err != nil {
		return err
	}
	journalPath := runtimeTransactionJournalPath(configDir)
	if err := writeRuntimeTransactionJournal(journalPath, journal); err != nil {
		return err
	}
	rollback := func(cause error) error {
		if err := restoreRuntimeTransaction(configDir, journal); err != nil {
			return errors.Join(cause, fmt.Errorf("restore runtime transaction: %w", err))
		}
		if journal.Phase == "reload-pending" {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return errors.Join(cause, applier.finishRuntimeRecovery(cleanupCtx, runtimeTransactionRecovery{JournalPath: journalPath, Journal: journal, NeedsReload: true}))
		}
		return errors.Join(cause, clearRuntimeTransactionJournal(journalPath))
	}
	if err := runtimeTransactionStage(applier.options.TransactionHook, runtimeTransactionPersistedStage); err != nil {
		if errors.Is(err, ErrRuntimeTransactionInterrupted) {
			return err
		}
		return rollback(err)
	}
	if err := replaceRuntimeFiles(configDir, journal, applier.options.TransactionHook); err != nil {
		if errors.Is(err, ErrRuntimeTransactionInterrupted) {
			return err
		}
		return rollback(err)
	}
	if err := markRuntimeTransactionPhase(journalPath, journal, "reload-pending"); err != nil {
		return rollback(err)
	}
	journal.Phase = "reload-pending"

	if err := runtimeTransactionStage(applier.options.TransactionHook, runtimeTransactionBeforeReloadStage); err != nil {
		if errors.Is(err, ErrRuntimeTransactionInterrupted) {
			return err
		}
		return rollback(err)
	}
	if err := applier.reloadSway(ctx); err != nil {
		return rollback(fmt.Errorf("reload Sway: %w", err))
	}
	if err := runtimeTransactionStage(applier.options.TransactionHook, runtimeTransactionAfterReloadStage); err != nil {
		if errors.Is(err, ErrRuntimeTransactionInterrupted) {
			return err
		}
		return rollback(err)
	}
	novaKeysEnabled := strings.Contains(artifact.Sway.Text, "exec_always --no-startup-id ~/.local/bin/novakeys")
	if novaKeysEnabled && !runtimeExecutableAvailable(applier.options.NovaKeysBinary) {
		return rollback(fmt.Errorf("NOVA Keys executable is missing or not executable"))
	}
	if err := applier.reconcileNovaKeys(ctx, novaKeysEnabled); err != nil {
		return rollback(fmt.Errorf("reload NOVA Keys: %w", err))
	}
	if err := runtimeTransactionStage(applier.options.TransactionHook, runtimeTransactionBeforeCommitStage); err != nil {
		if errors.Is(err, ErrRuntimeTransactionInterrupted) {
			return err
		}
		return rollback(err)
	}
	if err := markRuntimeTransactionCommitted(journalPath, journal); err != nil {
		// A rename may have succeeded before its directory sync failed.
		// Reassert rollback intent before restoring the previous generation.
		pendingErr := writeRuntimeTransactionJournal(journalPath, journal)
		return rollback(errors.Join(err, pendingErr))
	}
	if err := runtimeTransactionStage(applier.options.TransactionHook, runtimeTransactionCommittedStage); err != nil {
		return err
	}
	if err := clearRuntimeTransactionJournal(journalPath); err != nil {
		return err
	}
	return nil
}

func (applier *SwayRuntimeApplier) finishRuntimeRecovery(ctx context.Context, recovery runtimeTransactionRecovery) error {
	if err := applier.reloadSway(ctx); err != nil {
		return err
	}
	oldSway := []byte(nil)
	for _, entry := range recovery.Journal.Entries {
		if entry.Path == "sway/config" && entry.Old.Present {
			oldSway = entry.Old.Data
			break
		}
	}
	novaKeysEnabled := strings.Contains(string(oldSway), "exec_always --no-startup-id ~/.local/bin/novakeys")
	if err := applier.reconcileNovaKeys(ctx, novaKeysEnabled); err != nil {
		return err
	}
	return clearRuntimeTransactionJournal(recovery.JournalPath)
}

func (applier *SwayRuntimeApplier) reconcileNovaKeys(ctx context.Context, enabled bool) error {
	if applier.options.NovaKeysBinary == "" || !runtimeExecutableAvailable(applier.options.NovaKeysBinary) {
		return nil
	}
	message := "close"
	if enabled {
		message = "reload-config"
	}
	var lastErr error
	attempts := 1
	if enabled {
		attempts = 3
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if _, lastErr = applier.run(ctx, applier.options.NovaKeysBinary, []string{"-m", message}, nil); lastErr == nil {
			return nil
		}
		if attempt+1 < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return lastErr
}

func (applier *SwayRuntimeApplier) run(ctx context.Context, name string, args, environment []string) ([]byte, error) {
	if strings.TrimSpace(name) == "" || len(name) > 256 {
		return nil, fmt.Errorf("runtime command is invalid")
	}
	commandContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return applier.options.CommandRunner.Run(commandContext, name, args, environment)
}

func (applier *SwayRuntimeApplier) runtimeEnvironment() []string {
	return []string{"XDG_RUNTIME_DIR=" + applier.runtimeDir}
}

func (applier *SwayRuntimeApplier) runtimeValidationEnvironment() []string {
	environment := applier.runtimeEnvironment()
	return append(environment,
		"WLR_BACKENDS=headless",
		"WLR_RENDERER=pixman",
		"WLR_LIBINPUT_NO_DEVICES=1",
	)
}

func (applier *SwayRuntimeApplier) reloadSway(ctx context.Context) error {
	validateSocket := applier.options.ValidateSocket
	if validateSocket == nil {
		validateSocket = validateSwaySocket
	}
	socket := applier.options.SwaySocket
	if socket == "" {
		var err error
		socket, err = discoverSwaySocket()
		if err != nil {
			return err
		}
	} else if err := validateSocket(socket); err != nil {
		return err
	}
	environment := applier.runtimeEnvironment()
	environment = append(environment, "SWAYSOCK="+socket)
	_, err := applier.run(ctx, applier.options.SwayMsgBinary, []string{"reload"}, environment)
	return err
}

func validateRuntimePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || len(path) > 4096 || strings.ContainsRune(path, 0) {
		return fmt.Errorf("path is invalid")
	}
	return nil
}

func safeRuntimeDir(options RuntimeApplierOptions) (string, error) {
	uid := os.Getuid()
	pathResolver := options.RuntimeDirPath
	if pathResolver == nil {
		pathResolver = func(currentUID int) string {
			return filepath.Join("/run", "user", strconv.Itoa(currentUID))
		}
	}
	path := pathResolver(uid)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 256 || strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is unsafe; expected a private current-user runtime directory")
	}
	stat := options.RuntimeDirInfo
	if stat == nil {
		stat = os.Lstat
	}
	info, err := stat(path)
	if err != nil {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is unavailable: %w", err)
	}
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o700 != 0o700 || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is unsafe; expected a private current-user runtime directory")
	}
	fileStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(fileStat.Uid) != uid {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is unsafe; directory is not owned by the current user")
	}
	return path, nil
}

func ensureRuntimeDirectory(path string) error {
	if err := validateRuntimePath(path); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(clean)
		if parent != clean {
			if err := ensureRuntimeDirectory(parent); err != nil {
				return err
			}
		}
		if err := os.Mkdir(clean, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create runtime directory: %w", err)
		}
		info, err = os.Lstat(clean)
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime directory is unsafe")
	}
	return nil
}

func readRuntimeManagedFile(path string) (runtimeManagedFile, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeManagedFile{}, nil
	}
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return runtimeManagedFile{}, fmt.Errorf("managed runtime path is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeManagedFile{}, fmt.Errorf("read managed runtime file: %w", err)
	}
	return runtimeManagedFile{data: data, present: true}, nil
}

func readRuntimeManifest(path string) (runtimeManifest, error) {
	file, err := readRuntimeManagedFile(path)
	if err != nil {
		return runtimeManifest{}, err
	}
	if !file.present {
		return runtimeManifest{Version: 1}, nil
	}
	return decodeRuntimeManifest(file.data)
}

func decodeRuntimeManifest(data []byte) (runtimeManifest, error) {
	var manifest runtimeManifest
	if err := decodeStrict(data, &manifest); err != nil || manifest.Version != 1 || len(manifest.Layouts) > 32 {
		return runtimeManifest{}, fmt.Errorf("runtime manifest is invalid")
	}
	for index, code := range manifest.Layouts {
		if !isSafeRuntimeLanguageCode(code) || (index > 0 && manifest.Layouts[index-1] >= code) {
			return runtimeManifest{}, fmt.Errorf("runtime manifest layout list is invalid")
		}
	}
	return manifest, nil
}

func stageRuntimeFile(directory string, data []byte) (string, error) {
	temporary, err := os.CreateTemp(directory, ".novakiosk-agent-runtime-*")
	if err != nil {
		return "", fmt.Errorf("stage runtime file: %w", err)
	}
	path := temporary.Name()
	cleanup := func() { temporary.Close(); os.Remove(path) }
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func atomicRuntimeWrite(path string, data []byte) error {
	directory := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil {
		if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed runtime path is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect runtime path: %w", err)
	}
	temporary, err := stageRuntimeFile(directory, data)
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return fmt.Errorf("replace runtime file: %w", err)
	}
	return syncRuntimeDirectory(directory)
}

func syncRuntimeDirectory(directory string) error {
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func runtimeExecutableAvailable(path string) bool {
	if strings.ContainsRune(path, filepath.Separator) {
		info, err := os.Stat(path)
		return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
	}
	_, err := exec.LookPath(path)
	return err == nil
}

func discoverSwaySocket() (string, error) {
	if socket := strings.TrimSpace(os.Getenv("SWAYSOCK")); socket != "" {
		if err := validateSwaySocket(socket); err != nil {
			return "", err
		}
		return socket, nil
	}
	pattern := filepath.Join("/run", "user", fmt.Sprint(os.Getuid()), "sway-ipc.*.sock")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("SWAYSOCK: %w", errGraphicalSessionUnavailable)
	}
	sort.Strings(matches)
	for _, match := range matches {
		if err := validateSwaySocket(match); err == nil {
			return match, nil
		}
	}
	return "", fmt.Errorf("no safe Sway socket is available")
}

func validateSwaySocket(path string) error {
	if !filepath.IsAbs(path) || len(path) > 512 || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("SWAYSOCK is unsafe")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return errGraphicalSessionUnavailable
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("SWAYSOCK is not a socket")
	}
	return nil
}
