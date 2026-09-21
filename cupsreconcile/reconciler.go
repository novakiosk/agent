package cupsreconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/novakiosk/agent/cupsjob"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(context.Context, string, []string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, path, args...)
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin"}
	output, err := command.Output()
	if err != nil {
		return nil, errors.New("cups reconcile: fixed command failed")
	}
	if len(output) > MaxMessageBytes {
		return nil, errors.New("cups reconcile: fixed command output exceeds bound")
	}
	return output, nil
}

type Reconciler struct {
	DefaultRunner cupsjob.CommandRunner
	StateDir      string
	Profile       string
	Runner        CommandRunner
}

type Applier interface {
	Apply(context.Context, Desired) HelperResult
}

// DirectApplier is the negotiated v2 central-queue path. It is intentionally
// separate from Applier so v1 kiosk proxy handling cannot accept direct mode.
type DirectApplier interface {
	ApplyV2(context.Context, DesiredV2) HelperResult
}

func (reconciler Reconciler) Apply(ctx context.Context, desired Desired) HelperResult {
	failure := HelperResult{Version: Version, Type: "printer.helper.result", DesiredHash: desired.DesiredHash, Result: ResultFailed, ErrorCategory: ErrorHelper}
	if ctx == nil || (reconciler.Profile != "kiosk" && reconciler.Profile != "print-bridge") || validatePrivateDirectory(reconciler.StateDir) != nil || desired.Validate() != nil {
		failure.ErrorCategory = ErrorInvalid
		return failure
	}
	request := HelperRequest{DefaultQueue: desired.DefaultQueue, Version: Version, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Normalize().Queues}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > MaxMessageBytes {
		failure.ErrorCategory = ErrorInvalid
		return failure
	}
	requestPath := filepath.Join(reconciler.StateDir, HelperRequestName)
	resultPath := filepath.Join(reconciler.StateDir, HelperResultName)
	if err := saveUserAtomic(reconciler.StateDir, requestPath, encoded); err != nil {
		return failure
	}
	_ = os.Remove(resultPath)
	runner := reconciler.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	unit := "novakiosk-cups-reconcile@" + reconciler.Profile + ".service"
	if _, err := runner.Run(ctx, "/usr/bin/systemctl", []string{"start", unit}); err != nil {
		return failure
	}
	result, err := loadHelperResult(resultPath, desired.DesiredHash)
	if err != nil {
		return failure
	}
	return result
}

func (reconciler Reconciler) ApplyV2(ctx context.Context, desired DesiredV2) HelperResult {
	failure := HelperResult{Version: Version2, Type: "printer.helper.result", DesiredHash: desired.DesiredHash, Result: ResultFailed, ErrorCategory: ErrorHelper}
	if ctx == nil || reconciler.Profile != "print-bridge" || validatePrivateDirectory(reconciler.StateDir) != nil || desired.Validate() != nil {
		failure.ErrorCategory = ErrorInvalid
		return failure
	}
	request := HelperRequestV2{Version: Version2, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Normalize().Queues}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > MaxMessageBytes {
		failure.ErrorCategory = ErrorInvalid
		return failure
	}
	requestPath := filepath.Join(reconciler.StateDir, HelperRequestName)
	resultPath := filepath.Join(reconciler.StateDir, HelperResultName)
	if err := saveUserAtomic(reconciler.StateDir, requestPath, encoded); err != nil {
		return failure
	}
	_ = os.Remove(resultPath)
	runner := reconciler.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	if _, err := runner.Run(ctx, "/usr/bin/systemctl", []string{"start", "novakiosk-cups-reconcile@print-bridge.service"}); err != nil {
		return failure
	}
	result, err := loadHelperResultV2(resultPath, desired.DesiredHash)
	if err != nil {
		return failure
	}
	return result
}

func loadHelperResult(path, desiredHash string) (HelperResult, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return HelperResult{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result HelperResult
	if err := decoder.Decode(&result); err != nil {
		return HelperResult{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return HelperResult{}, errors.New("cups reconcile: malformed helper result")
	}
	if result.Version != Version || result.Type != "printer.helper.result" || result.DesiredHash != desiredHash || (result.Result != ResultApplied && result.Result != ResultFailed) || (result.Result == ResultApplied && result.ErrorCategory != "") || (result.Result == ResultFailed && result.ErrorCategory == "") {
		return HelperResult{}, errors.New("cups reconcile: invalid helper result")
	}
	return result, nil
}

func loadHelperResultV2(path, desiredHash string) (HelperResult, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return HelperResult{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result HelperResult
	if err := decoder.Decode(&result); err != nil {
		return HelperResult{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return HelperResult{}, errors.New("cups reconcile: malformed helper v2 result")
	}
	if result.Version != Version2 || result.Type != "printer.helper.result" || result.DesiredHash != desiredHash || (result.Result != ResultApplied && result.Result != ResultFailed) || (result.Result == ResultApplied && result.ErrorCategory != "") || (result.Result == ResultFailed && result.ErrorCategory == "") {
		return HelperResult{}, errors.New("cups reconcile: invalid helper v2 result")
	}
	return result, nil
}

func validatePrivateDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("cups reconcile: state directory is required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("cups reconcile: unsafe state directory")
	}
	return nil
}

func saveUserAtomic(directory, path string, data []byte) error {
	if err := validatePrivateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".cups-request-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > limit {
		return nil, fmt.Errorf("cups reconcile: unsafe state file")
	}
	return os.ReadFile(path)
}
