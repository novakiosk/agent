package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	runtimeTransactionJournalName       = ".novakiosk-agent-runtime-transaction.json"
	runtimeTransactionVersion           = 1
	runtimeTransactionMaxJournalBytes   = 2 * 1024 * 1024
	runtimeTransactionMaxSnapshotBytes  = 512 * 1024
	runtimeTransactionMaxEntries        = 128
	runtimeTransactionPersistedStage    = "transaction-persisted"
	runtimeTransactionBeforeReloadStage = "before-reload"
	runtimeTransactionAfterReloadStage  = "after-reload"
	runtimeTransactionBeforeCommitStage = "before-commit"
	runtimeTransactionCommittedStage    = "transaction-committed"
)

type runtimeTransactionSnapshot struct {
	Present bool   `json:"present"`
	Data    []byte `json:"data"`
}

type runtimeTransactionEntry struct {
	Path string                     `json:"path"`
	Old  runtimeTransactionSnapshot `json:"old"`
	New  runtimeTransactionSnapshot `json:"new"`
}

type runtimeTransactionJournal struct {
	Version      int                       `json:"version"`
	Phase        string                    `json:"phase"`
	ArtifactHash string                    `json:"artifactHash"`
	Entries      []runtimeTransactionEntry `json:"entries"`
}

type runtimeTransactionRecovery struct {
	JournalPath string
	Journal     runtimeTransactionJournal
	NeedsReload bool
}

func runtimeTransactionJournalPath(configDir string) string {
	return filepath.Join(configDir, "novakeys", runtimeTransactionJournalName)
}

func runtimeTransactionStage(hook RuntimeTransactionHook, stage string) error {
	if hook == nil {
		return nil
	}
	return hook(stage)
}

func buildRuntimeTransactionJournal(configDir string, managed map[string][]byte, previous map[string]runtimeManagedFile, artifactHash string) (runtimeTransactionJournal, error) {
	if len(artifactHash) != 64 || strings.Trim(artifactHash, "0123456789abcdef") != "" {
		return runtimeTransactionJournal{}, fmt.Errorf("runtime transaction artifact hash is invalid")
	}
	paths := make(map[string]bool, len(managed)+len(previous))
	for path := range managed {
		paths[path] = true
	}
	for path := range previous {
		paths[path] = true
	}
	if len(paths) == 0 || len(paths) > runtimeTransactionMaxEntries {
		return runtimeTransactionJournal{}, fmt.Errorf("runtime transaction file set is invalid")
	}

	relativePaths := make([]string, 0, len(paths))
	for path := range paths {
		relative, err := runtimeTransactionRelativePath(configDir, path)
		if err != nil {
			return runtimeTransactionJournal{}, err
		}
		relativePaths = append(relativePaths, relative)
	}
	sort.Strings(relativePaths)
	journal := runtimeTransactionJournal{
		Version:      runtimeTransactionVersion,
		Phase:        "prepared",
		ArtifactHash: artifactHash,
		Entries:      make([]runtimeTransactionEntry, 0, len(relativePaths)),
	}
	oldBytes, newBytes := 0, 0
	for _, relative := range relativePaths {
		path, err := runtimeTransactionAbsolutePath(configDir, relative)
		if err != nil {
			return runtimeTransactionJournal{}, err
		}
		entry := runtimeTransactionEntry{Path: relative}
		if old, ok := previous[path]; ok && old.present {
			entry.Old = runtimeTransactionSnapshot{Present: true, Data: append([]byte(nil), old.data...)}
		}
		if data, ok := managed[path]; ok {
			entry.New = runtimeTransactionSnapshot{Present: true, Data: append([]byte(nil), data...)}
		}
		if entry.Old.Present {
			if err := validateRuntimeTransactionData(entry.Old.Data); err != nil {
				return runtimeTransactionJournal{}, fmt.Errorf("old runtime transaction data for %s: %w", relative, err)
			}
			oldBytes += len(entry.Old.Data)
		}
		if entry.New.Present {
			if err := validateRuntimeTransactionData(entry.New.Data); err != nil {
				return runtimeTransactionJournal{}, fmt.Errorf("new runtime transaction data for %s: %w", relative, err)
			}
			newBytes += len(entry.New.Data)
		}
		journal.Entries = append(journal.Entries, entry)
	}
	if oldBytes > runtimeTransactionMaxSnapshotBytes || newBytes > runtimeTransactionMaxSnapshotBytes {
		return runtimeTransactionJournal{}, fmt.Errorf("runtime transaction snapshot is too large")
	}
	if err := validateRuntimeTransactionJournal(journal); err != nil {
		return runtimeTransactionJournal{}, err
	}
	return journal, nil
}

func writeRuntimeTransactionJournal(path string, journal runtimeTransactionJournal) error {
	if err := validateRuntimeTransactionJournal(journal); err != nil {
		return err
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return fmt.Errorf("encode runtime transaction journal: %w", err)
	}
	if len(data) > runtimeTransactionMaxJournalBytes {
		return fmt.Errorf("runtime transaction journal is too large")
	}
	return atomicRuntimeWrite(path, data)
}

func markRuntimeTransactionCommitted(path string, journal runtimeTransactionJournal) error {
	return markRuntimeTransactionPhase(path, journal, "committed")
}

func markRuntimeTransactionPhase(path string, journal runtimeTransactionJournal, phase string) error {
	journal.Phase = phase
	return writeRuntimeTransactionJournal(path, journal)
}

func clearRuntimeTransactionJournal(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime transaction journal is unsafe")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear runtime transaction journal: %w", err)
	}
	return syncRuntimeDirectory(filepath.Dir(path))
}

func replaceRuntimeFiles(configDir string, journal runtimeTransactionJournal, hook RuntimeTransactionHook) error {
	for _, entry := range journal.Entries {
		if !entry.New.Present {
			continue
		}
		path, err := runtimeTransactionAbsolutePath(configDir, entry.Path)
		if err != nil {
			return err
		}
		if err := atomicRuntimeWrite(path, entry.New.Data); err != nil {
			return err
		}
		if err := runtimeTransactionStage(hook, "replacement:"+entry.Path); err != nil {
			return err
		}
	}
	for _, entry := range journal.Entries {
		if entry.New.Present || !entry.Old.Present {
			continue
		}
		path, err := runtimeTransactionAbsolutePath(configDir, entry.Path)
		if err != nil {
			return err
		}
		if err := removeRuntimeFile(path); err != nil {
			return err
		}
		if err := runtimeTransactionStage(hook, "removal:"+entry.Path); err != nil {
			return err
		}
	}
	return nil
}

func restoreRuntimeTransaction(configDir string, journal runtimeTransactionJournal) error {
	for _, entry := range journal.Entries {
		path, err := runtimeTransactionAbsolutePath(configDir, entry.Path)
		if err != nil {
			return err
		}
		if entry.Old.Present {
			if err := atomicRuntimeWrite(path, entry.Old.Data); err != nil {
				return err
			}
			continue
		}
		if err := removeRuntimeFile(path); err != nil {
			return err
		}
	}
	return nil
}

func recoverRuntimeTransaction(configDir string) (runtimeTransactionRecovery, error) {
	if err := validateRuntimePath(configDir); err != nil {
		return runtimeTransactionRecovery{}, err
	}
	configInfo, err := os.Lstat(configDir)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeTransactionRecovery{}, nil
	}
	if err != nil || configInfo == nil || !configInfo.IsDir() || configInfo.Mode()&os.ModeSymlink != 0 {
		return runtimeTransactionRecovery{}, fmt.Errorf("runtime config directory is unsafe")
	}
	novaKeysDir := filepath.Join(configDir, "novakeys")
	novaInfo, err := os.Lstat(novaKeysDir)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeTransactionRecovery{}, nil
	}
	if err != nil || novaInfo == nil || !novaInfo.IsDir() || novaInfo.Mode()&os.ModeSymlink != 0 {
		return runtimeTransactionRecovery{}, fmt.Errorf("NOVA Keys runtime directory is unsafe")
	}
	journalPath := runtimeTransactionJournalPath(configDir)
	journalInfo, err := os.Lstat(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeTransactionRecovery{}, nil
	}
	if err != nil || journalInfo == nil || !journalInfo.Mode().IsRegular() || journalInfo.Mode()&os.ModeSymlink != 0 {
		return runtimeTransactionRecovery{}, fmt.Errorf("runtime transaction journal is unsafe")
	}
	if journalInfo.Size() < 0 || journalInfo.Size() > runtimeTransactionMaxJournalBytes {
		return runtimeTransactionRecovery{}, fmt.Errorf("runtime transaction journal is too large")
	}
	swayDir := filepath.Join(configDir, "sway")
	swayInfo, err := os.Lstat(swayDir)
	if err != nil || swayInfo == nil || !swayInfo.IsDir() || swayInfo.Mode()&os.ModeSymlink != 0 {
		return runtimeTransactionRecovery{}, fmt.Errorf("Sway runtime directory is unsafe")
	}
	journalData, err := os.ReadFile(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeTransactionRecovery{}, nil
	}
	if err != nil {
		return runtimeTransactionRecovery{}, fmt.Errorf("read runtime transaction journal: %w", err)
	}
	if len(journalData) > runtimeTransactionMaxJournalBytes {
		return runtimeTransactionRecovery{}, fmt.Errorf("runtime transaction journal is too large")
	}
	var journal runtimeTransactionJournal
	decoder := json.NewDecoder(bytes.NewReader(journalData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return runtimeTransactionRecovery{}, fmt.Errorf("runtime transaction journal is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return runtimeTransactionRecovery{}, fmt.Errorf("runtime transaction journal has trailing data")
	}
	if err := validateRuntimeTransactionJournal(journal); err != nil {
		return runtimeTransactionRecovery{}, err
	}
	if journal.Phase == "committed" && runtimeTransactionMatchesCurrent(configDir, journal) {
		return runtimeTransactionRecovery{}, clearRuntimeTransactionJournal(journalPath)
	}
	if err := restoreRuntimeTransaction(configDir, journal); err != nil {
		return runtimeTransactionRecovery{}, fmt.Errorf("restore runtime transaction: %w", err)
	}
	needsReload := journal.Phase == "reload-pending" || journal.Phase == "committed"
	if !needsReload {
		return runtimeTransactionRecovery{}, clearRuntimeTransactionJournal(journalPath)
	}
	return runtimeTransactionRecovery{JournalPath: journalPath, Journal: journal, NeedsReload: true}, nil
}

func runtimeTransactionMatchesCurrent(configDir string, journal runtimeTransactionJournal) bool {
	for _, entry := range journal.Entries {
		path, err := runtimeTransactionAbsolutePath(configDir, entry.Path)
		if err != nil {
			return false
		}
		current, err := readRuntimeManagedFile(path)
		if err != nil || current.present != entry.New.Present || (current.present && !bytes.Equal(current.data, entry.New.Data)) {
			return false
		}
	}
	return true
}

func validateRuntimeTransactionJournal(journal runtimeTransactionJournal) error {
	if journal.Version != runtimeTransactionVersion || (journal.Phase != "prepared" && journal.Phase != "reload-pending" && journal.Phase != "committed") || len(journal.Entries) == 0 || len(journal.Entries) > runtimeTransactionMaxEntries {
		return fmt.Errorf("runtime transaction journal is invalid")
	}
	if len(journal.ArtifactHash) != 64 || strings.Trim(journal.ArtifactHash, "0123456789abcdef") != "" {
		return fmt.Errorf("runtime transaction journal artifact hash is invalid")
	}
	seen := make(map[string]bool, len(journal.Entries))
	oldBytes, newBytes := 0, 0
	hasSway, hasNova, hasManifest := false, false, false
	hasNewSway, hasNewNova, hasNewManifest := false, false, false
	for index, entry := range journal.Entries {
		if entry.Path == "" || (index > 0 && journal.Entries[index-1].Path >= entry.Path) || seen[entry.Path] {
			return fmt.Errorf("runtime transaction journal paths are not sorted")
		}
		seen[entry.Path] = true
		if _, err := runtimeTransactionRelativePathFromString(entry.Path); err != nil {
			return err
		}
		if err := validateRuntimeTransactionSnapshot(entry.Old); err != nil {
			return err
		}
		if err := validateRuntimeTransactionSnapshot(entry.New); err != nil {
			return err
		}
		if entry.Old.Present {
			oldBytes += len(entry.Old.Data)
		}
		if entry.New.Present {
			newBytes += len(entry.New.Data)
		}
		switch {
		case entry.Path == "sway/config":
			hasSway = true
			hasNewSway = entry.New.Present
		case entry.Path == "novakeys/config":
			hasNova = true
			hasNewNova = entry.New.Present
		case entry.Path == "novakeys/"+runtimeManifestName:
			hasManifest = true
			hasNewManifest = entry.New.Present
		}
	}
	if !hasSway || !hasNova || !hasManifest || !hasNewSway || !hasNewNova || !hasNewManifest || oldBytes > runtimeTransactionMaxSnapshotBytes || newBytes > runtimeTransactionMaxSnapshotBytes {
		return fmt.Errorf("runtime transaction journal file set is invalid")
	}
	oldManifest, newManifest := runtimeTransactionManifest(journal, false), runtimeTransactionManifest(journal, true)
	oldManifestCodes, newManifestCodes := make(map[string]bool), make(map[string]bool)
	if oldManifest != nil {
		for _, code := range oldManifest.Layouts {
			if !isSafeRuntimeLanguageCode(code) {
				return fmt.Errorf("runtime transaction old manifest contains unsafe layout")
			}
			oldManifestCodes[code] = true
		}
	}
	for _, entry := range journal.Entries {
		if strings.HasPrefix(entry.Path, "novakeys/layout-") && entry.Old.Present && oldManifest == nil {
			return fmt.Errorf("runtime transaction old layout has no manifest")
		}
	}
	if newManifest == nil {
		return fmt.Errorf("runtime transaction new manifest is missing")
	}
	for _, code := range newManifest.Layouts {
		if !isSafeRuntimeLanguageCode(code) {
			return fmt.Errorf("runtime transaction new manifest contains unsafe layout")
		}
		newManifestCodes[code] = true
	}
	for _, entry := range journal.Entries {
		if !strings.HasPrefix(entry.Path, "novakeys/layout-") {
			continue
		}
		code := strings.TrimSuffix(strings.TrimPrefix(entry.Path, "novakeys/layout-"), ".toml")
		if entry.Old.Present != oldManifestCodes[code] || entry.New.Present != newManifestCodes[code] {
			return fmt.Errorf("runtime transaction layout is not manifest-managed")
		}
	}
	return nil
}

func validateRuntimeTransactionSnapshot(snapshot runtimeTransactionSnapshot) error {
	if !snapshot.Present {
		if len(snapshot.Data) != 0 {
			return fmt.Errorf("runtime transaction missing snapshot has data")
		}
		return nil
	}
	return validateRuntimeTransactionData(snapshot.Data)
}

func validateRuntimeTransactionData(data []byte) error {
	if len(data) > runtimeTransactionMaxSnapshotBytes {
		return fmt.Errorf("runtime transaction data is too large")
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("runtime transaction data is not UTF-8")
	}
	for _, character := range string(data) {
		if character == 0 || (character < 0x20 && character != '\t' && character != '\n' && character != '\r') || character == 0x7f {
			return fmt.Errorf("runtime transaction data contains an invalid control")
		}
	}
	return nil
}

func runtimeTransactionManifest(journal runtimeTransactionJournal, newest bool) *runtimeManifest {
	for _, entry := range journal.Entries {
		if entry.Path != "novakeys/"+runtimeManifestName {
			continue
		}
		snapshot := entry.Old
		if newest {
			snapshot = entry.New
		}
		if !snapshot.Present {
			return nil
		}
		manifest, err := decodeRuntimeManifest(snapshot.Data)
		if err != nil {
			return nil
		}
		return &manifest
	}
	return nil
}

func runtimeTransactionRelativePath(configDir, path string) (string, error) {
	relative, err := filepath.Rel(configDir, path)
	if err != nil {
		return "", fmt.Errorf("runtime transaction path is invalid")
	}
	return runtimeTransactionRelativePathFromString(filepath.ToSlash(relative))
}

func runtimeTransactionRelativePathFromString(relative string) (string, error) {
	if relative == "" || strings.ContainsRune(relative, '\x00') || filepath.IsAbs(relative) || filepath.Clean(filepath.FromSlash(relative)) != filepath.FromSlash(relative) {
		return "", fmt.Errorf("runtime transaction path is unsafe")
	}
	if relative == "sway/config" || relative == "novakeys/config" || relative == "novakeys/"+runtimeManifestName {
		return relative, nil
	}
	if strings.HasPrefix(relative, "novakeys/layout-") && strings.HasSuffix(relative, ".toml") {
		code := strings.TrimSuffix(strings.TrimPrefix(relative, "novakeys/layout-"), ".toml")
		if isSafeRuntimeLanguageCode(code) && "novakeys/layout-"+code+".toml" == relative {
			return relative, nil
		}
	}
	return "", fmt.Errorf("runtime transaction path is not managed")
}

func runtimeTransactionAbsolutePath(configDir, relative string) (string, error) {
	clean, err := runtimeTransactionRelativePathFromString(relative)
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, filepath.FromSlash(clean)), nil
}

func removeRuntimeFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed runtime path is unsafe")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove runtime file: %w", err)
	}
	return syncRuntimeDirectory(filepath.Dir(path))
}
