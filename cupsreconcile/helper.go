package cupsreconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/novakiosk/agent/printer"
)

type HelperConfig struct {
	StateDir       string
	ManifestDir    string
	Profile        string
	Runner         CommandRunner
	CUPSConfigPath string
	// PPDDir is an installation-owned fixed directory. It is injectable in
	// tests but never comes from a desired payload.
	PPDDir string
}

type ownedManifest struct {
	Version int      `json:"version"`
	Queues  []string `json:"queues"`
	// Claims are staged deterministic names for a managed queue transaction.
	// They make a crash between lpadmin and the final manifest commit safely
	// retryable without claiming arbitrary NOVA-looking or implicitclass queues.
	Claims   []string                     `json:"claims,omitempty"`
	Settings map[string][]string          `json:"settings"`
	Defaults map[string]map[string]string `json:"defaults,omitempty"`
}

type HelperRequestV2 struct {
	Version     int     `json:"version"`
	Type        string  `json:"type"`
	DesiredHash string  `json:"desiredHash"`
	Queues      []Queue `json:"queues"`
}

func ProfilePaths(profile string) (stateDir, manifestDir string, ok bool) {
	switch profile {
	case "kiosk":
		return "/var/lib/novakiosk-agentd-helpers/kiosk", "/var/lib/novakiosk-cups-helper", true
	case "print-bridge":
		return "/var/lib/novakiosk-agentd-helpers/print-bridge", "/var/lib/novakiosk-cups-helper", true
	default:
		return "", "", false
	}
}

func ApplyHelper(ctx context.Context, config HelperConfig) error {
	if ctx == nil || (config.Profile != "kiosk" && config.Profile != "print-bridge") || validatePrivateDirectory(config.StateDir) != nil {
		return errors.New("cups reconcile: invalid helper profile")
	}
	if err := os.MkdirAll(config.ManifestDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(config.ManifestDir, 0o700); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(config.ManifestDir, 0, 0); err != nil {
			return err
		}
	}
	lock, err := os.OpenFile(filepath.Join(config.ManifestDir, config.Profile+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	requestPath := filepath.Join(config.StateDir, HelperRequestName)
	version, err := helperRequestVersion(requestPath)
	if err != nil {
		return err
	}
	runner := config.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	if version == Version2 {
		if config.Profile != "print-bridge" {
			return errors.New("cups reconcile: direct queues require print-bridge profile")
		}
		requestV2, loadErr := loadHelperRequestV2(requestPath)
		if loadErr != nil {
			return loadErr
		}
		result := HelperResult{Version: Version2, Type: "printer.helper.result", DesiredHash: requestV2.DesiredHash, Result: ResultApplied}
		if applyErr := applyDirectQueues(ctx, runner, config, requestV2); applyErr != nil {
			result.Result = ResultFailed
			result.ErrorCategory = ErrorApply
		}
		return writeHelperResult(config.StateDir, result)
	}
	if version != Version {
		return errors.New("cups reconcile: unsupported helper request version")
	}
	request, err := loadHelperRequest(requestPath)
	if err != nil {
		return err
	}
	result := HelperResult{Version: Version, Type: "printer.helper.result", DesiredHash: request.DesiredHash, Result: ResultApplied}
	if err := applyQueues(ctx, runner, config, request); err != nil {
		result.Result = ResultFailed
		result.ErrorCategory = ErrorApply
	}
	return writeHelperResult(config.StateDir, result)
}

func helperRequestVersion(path string) (int, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return 0, err
	}
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || (envelope.Version != Version && envelope.Version != Version2) {
		return 0, errors.New("cups reconcile: malformed helper request")
	}
	return envelope.Version, nil
}

func loadHelperRequestV2(path string) (HelperRequestV2, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return HelperRequestV2{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request HelperRequestV2
	if err := decoder.Decode(&request); err != nil {
		return HelperRequestV2{}, errors.New("cups reconcile: malformed helper v2 request")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return HelperRequestV2{}, errors.New("cups reconcile: malformed helper v2 request")
	}
	desired := DesiredV2{Version: request.Version, Type: DesiredType, SessionID: "helper", DeviceID: "helper", DesiredHash: request.DesiredHash, Queues: request.Queues}
	if request.Type != "printer.helper.request" || desired.Validate() != nil {
		return HelperRequestV2{}, errors.New("cups reconcile: invalid helper v2 request")
	}
	request.Queues = desired.Normalize().Queues
	return request, nil
}

func applyDirectQueues(ctx context.Context, runner CommandRunner, config HelperConfig, request HelperRequestV2) error {
	if err := waitForCUPS(ctx, runner); err != nil {
		return err
	}
	if err := ensurePrintBridgeSharing(ctx, runner, config); err != nil {
		return err
	}
	manifestPath := filepath.Join(config.ManifestDir, config.Profile+".json")
	previous := loadManifest(manifestPath)
	previousOwned := make(map[string]string, len(previous.Queues)+len(previous.Claims))
	for _, name := range previous.Queues {
		previousOwned[strings.ToLower(name)] = name
	}
	for _, name := range previous.Claims {
		previousOwned[strings.ToLower(name)] = name
	}
	created := make([]string, 0, len(request.Queues))
	desired := make([]string, 0, len(request.Queues))
	settings := make(map[string][]string, len(request.Queues))
	// Only a successful complete snapshot proves absence. A failed lookup
	// must never authorize staging a claim for an unmanaged destination.
	existing, err := enumerateCUPSQueues(ctx, runner)
	if err != nil {
		return err
	}
	desiredNames := make(map[string]bool, len(request.Queues))
	// Resolve collisions before touching the manifest. An unowned existing
	// destination, even with a NOVA-looking name, is unmanaged evidence.
	for _, queue := range request.Queues {
		if queue.Mode != ModeDirect || !safeDirectQueueName(queue.LocalName) {
			return errors.New("cups reconcile: invalid direct queue")
		}
		folded := strings.ToLower(queue.LocalName)
		if desiredNames[folded] {
			return errors.New("cups reconcile: duplicate direct queue")
		}
		desiredNames[folded] = true
		if existing[strings.ToLower(queue.LocalName)] {
			if _, owned := previousOwned[strings.ToLower(queue.LocalName)]; !owned {
				return errors.New("cups reconcile: refusing unmanaged direct queue")
			}
		}
	}
	// Retain prior interrupted claims until obsolete queues are cleaned up.
	// New claims are only the validated deterministic names resolved above.
	claimNames := make([]string, 0, len(request.Queues))
	for _, queue := range request.Queues {
		claimNames = append(claimNames, queue.LocalName)
	}
	if err := stageOwnedClaims(config, manifestPath, &previous, Version2, claimNames); err != nil {
		return err
	}
	rollback := func() {
		for _, name := range created {
			_, _ = runner.Run(ctx, "/usr/sbin/lpadmin", []string{"-x", name})
		}
	}
	for _, queue := range request.Queues {
		if queue.Mode != ModeDirect || !safeDirectQueueName(queue.LocalName) {
			rollback()
			return errors.New("cups reconcile: invalid direct queue")
		}
		// The helper derives the URI and driver. The preflight snapshot and
		// root-owned manifest have already resolved ownership of this name.
		existed := existing[strings.ToLower(queue.LocalName)]
		if !existed {
			driver := DriverZebraZPLURI
			args := []string{"-p", queue.LocalName, "-E", "-v", "socket://" + queue.PrivateIP + ":9100", "-m", driver, "-D", queue.DisplayName, "-L", queue.Location, "-o", "printer-is-shared=true"}
			if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", args); err != nil {
				rollback()
				return err
			}
			created = append(created, queue.LocalName)
			existing[strings.ToLower(queue.LocalName)] = true
			if err := waitForCUPS(ctx, runner); err != nil {
				rollback()
				return err
			}
		}
		advertisedOutput, err := runner.Run(ctx, "/usr/bin/lpoptions", []string{"-p", queue.LocalName, "-l"})
		if err != nil {
			rollback()
			return err
		}
		advertised := printer.ParseQueueOptions(advertisedOutput)
		if queue.CustomMedia != nil && !customMediaAdvertised(*queue.CustomMedia, config.PPDDir, queue.LocalName) {
			rollback()
			return errors.New("cups reconcile: custom media is not advertised")
		}
		optionNames := make([]string, 0, len(queue.Options)+1)
		for _, option := range queue.Options {
			if !directOptionAllowed(option.Name) || !optionsAdvertised([]Option{option}, advertised) {
				rollback()
				return errors.New("cups reconcile: direct option is not advertised")
			}
			optionNames = append(optionNames, option.Name)
		}
		if queue.CustomMedia != nil {
			optionNames = append(optionNames, "PageSize")
		}
		if err := stageOwnedSettings(config, manifestPath, &previous, Version2, queue.LocalName, optionNames, advertised); err != nil {
			rollback()
			return err
		}
		restore, err := restoreOwnedOptions(config, previous, queue.LocalName, optionNames, advertised)
		if err != nil {
			rollback()
			return err
		}
		if existed {
			args := []string{"-p", queue.LocalName, "-E", "-v", "socket://" + queue.PrivateIP + ":9100", "-m", DriverZebraZPLURI, "-D", queue.DisplayName, "-L", queue.Location, "-o", "printer-is-shared=true"}
			if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", args); err != nil {
				rollback()
				return err
			}
			if err := waitForCUPS(ctx, runner); err != nil {
				rollback()
				return err
			}
		}
		for _, option := range restore {
			if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", []string{"-p", queue.LocalName, "-o", option.Name + "=" + option.Value}); err != nil {
				rollback()
				return err
			}
			if err := waitForCUPS(ctx, runner); err != nil {
				rollback()
				return err
			}
		}
		optionArgs := make([]string, 0, len(queue.Options)*2+2)
		for _, option := range queue.Options {
			optionArgs = append(optionArgs, "-o", option.Name+"="+option.Value)
		}
		if queue.CustomMedia != nil {
			optionArgs = append(optionArgs, "-o", "PageSize=Custom."+formatMM(queue.CustomMedia.Width)+"x"+formatMM(queue.CustomMedia.Height)+"mm")
		}
		if len(optionArgs) > 0 {
			args := append([]string{"-p", queue.LocalName}, optionArgs...)
			if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", args); err != nil {
				rollback()
				return err
			}
			if err := waitForCUPS(ctx, runner); err != nil {
				rollback()
				return err
			}
		}
		desired = append(desired, queue.LocalName)
		sort.Strings(optionNames)
		settings[settingsQueueName(previous, queue.LocalName)] = optionNames
	}
	// Cleanup applied queues and interrupted claims from the root-owned
	// previous manifest. Failed cleanup leaves their ownership staged for retry.
	obsolete := make([]string, 0, len(previousOwned))
	for _, name := range previousOwned {
		obsolete = append(obsolete, name)
	}
	sort.Strings(obsolete)
	for _, name := range obsolete {
		// Only a successful complete enumeration proves a staged claim never
		// created a queue, or that a previous cleanup already deleted it.
		if desiredNames[strings.ToLower(name)] || !existing[strings.ToLower(name)] {
			continue
		}
		if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", []string{"-x", name}); err != nil {
			return err
		}
		delete(existing, strings.ToLower(name))
		if err := waitForCUPS(ctx, runner); err != nil {
			return err
		}
	}
	sort.Strings(desired)
	return writeRootAtomic(config.ManifestDir, manifestPath, mustMarshal(ownedManifest{Version: Version2, Queues: desired, Settings: settings, Defaults: retainedDefaults(previous.Defaults, settings)}), -1, -1)
}

func stageOwnedClaims(config HelperConfig, manifestPath string, previous *ownedManifest, version int, names []string) error {
	claims := append(append([]string(nil), previous.Claims...), names...)
	sort.Strings(claims)
	staged := *previous
	staged.Version, staged.Claims = version, slices.Compact(claims)
	return persistStagedOwnership(config, manifestPath, previous, staged)
}

// Options are already validated against the queue's advertised capabilities.
// Retain their ownership, prior settings and pending queue claims until commit.
func stageOwnedSettings(config HelperConfig, manifestPath string, previous *ownedManifest, version int, queue string, names []string, advertised []printer.QueueOption) error {
	if len(names) == 0 {
		return nil
	}
	key := settingsQueueName(*previous, queue)
	owned := append(append([]string(nil), previous.Settings[key]...), names...)
	sort.Strings(owned)
	owned = slices.Compact(owned)
	if slices.Equal(owned, previous.Settings[key]) {
		return nil
	}
	originals := maps.Clone(previous.Defaults[key])
	if originals == nil {
		originals = make(map[string]string)
	}
	for _, name := range names {
		if slices.Contains(previous.Settings[key], name) {
			continue
		}
		value, err := captureOptionDefault(config, queue, name, advertised)
		if err != nil {
			return err
		}
		originals[name] = value
	}
	staged := *previous
	staged.Version = version
	staged.Defaults = maps.Clone(previous.Defaults)
	if staged.Defaults == nil {
		staged.Defaults = make(map[string]map[string]string)
	}
	staged.Defaults[key] = originals
	staged.Settings = maps.Clone(previous.Settings)
	staged.Settings[key] = owned
	return persistStagedOwnership(config, manifestPath, previous, staged)
}

func readAdvertisedOptions(ctx context.Context, runner CommandRunner, queue string) ([]printer.QueueOption, error) {
	if !safeQueueName(queue) {
		return nil, errors.New("cups reconcile: unsafe settings queue")
	}
	output, err := runner.Run(ctx, "/usr/bin/lpoptions", []string{"-p", queue, "-l"})
	if err != nil || len(output) > MaxMessageBytes {
		return nil, errors.New("cups reconcile: queue options unavailable")
	}
	return printer.ParseQueueOptions(output), nil
}

func captureOptionDefault(config HelperConfig, queue, name string, advertised []printer.QueueOption) (string, error) {
	value := ""
	for _, option := range advertised {
		if option.Name == name && option.Default != nil {
			value = *option.Default
			break
		}
	}
	if name == "PageSize" && value == "Custom.WIDTHxHEIGHT" {
		data, err := readQueuePPD(config.PPDDir, queue)
		if err != nil {
			return "", errors.New("cups reconcile: original custom media default unavailable")
		}
		value = ""
		found := false
		for line := range strings.SplitSeq(string(data), "\n") {
			if candidate, ok := strings.CutPrefix(strings.TrimSpace(line), "*DefaultPageSize:"); ok {
				if found {
					return "", errors.New("cups reconcile: ambiguous original media default")
				}
				found = true
				value = strings.TrimSpace(candidate)
			}
		}
		if value == "Custom.WIDTHxHEIGHT" {
			value = ""
		}
	}
	option := Option{Name: name, Value: value}
	if !validRestoredOption(config, queue, option, advertised) {
		return "", errors.New("cups reconcile: original option default unavailable")
	}
	return value, nil
}

func validRestoredOption(config HelperConfig, queue string, option Option, advertised []printer.QueueOption) bool {
	return option.Value != "Custom.WIDTHxHEIGHT" && safeQueueName(queue) && safeOptionToken(option.Name, 64) && safeOptionToken(option.Value, 128) && existingOptionsAdvertised([]Option{option}, advertised, config.PPDDir, queue)
}

func restoreOwnedOptions(config HelperConfig, previous ownedManifest, queue string, retained []string, advertised []printer.QueueOption) ([]Option, error) {
	var result []Option
	key := settingsQueueName(previous, queue)
	for _, name := range previous.Settings[key] {
		if slices.Contains(retained, name) {
			continue
		}
		value, known := previous.Defaults[key][name]
		option := Option{Name: name, Value: value}
		if !known || !validRestoredOption(config, queue, option, advertised) {
			return nil, errors.New("cups reconcile: original option default cannot be restored")
		}
		result = append(result, option)
	}
	return result, nil
}

// CUPS names are case-insensitive; retain the original settings identity.
func settingsQueueName(previous ownedManifest, queue string) string {
	for name := range previous.Settings {
		if strings.EqualFold(name, queue) {
			return name
		}
	}
	return queue
}

func retainedDefaults(previous map[string]map[string]string, settings map[string][]string) map[string]map[string]string {
	result := make(map[string]map[string]string)
	for queue, names := range settings {
		for _, name := range names {
			if value, known := previous[queue][name]; known {
				if result[queue] == nil {
					result[queue] = make(map[string]string)
				}
				result[queue][name] = value
			}
		}
	}
	return result
}

func persistStagedOwnership(config HelperConfig, manifestPath string, previous *ownedManifest, staged ownedManifest) error {
	data := mustMarshal(staged)
	if len(data) > MaxMessageBytes {
		return errors.New("cups reconcile: staged manifest too large")
	}
	if err := writeRootAtomic(config.ManifestDir, manifestPath, data, -1, -1); err != nil {
		return err
	}
	*previous = staged
	return nil
}

func enumerateCUPSQueues(ctx context.Context, runner CommandRunner) (map[string]bool, error) {
	existing := make(map[string]bool)
	output, err := runner.Run(ctx, "/usr/bin/lpstat", []string{"-e"})
	if err != nil {
		return nil, err
	}
	if len(output) > MaxMessageBytes {
		return nil, errors.New("cups reconcile: queue enumeration too large")
	}
	text := strings.TrimSuffix(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	if text != "" {
		for name := range strings.SplitSeq(text, "\n") {
			// Unrelated CUPS names may use a wider grammar. Membership
			// never grants ownership or supplies new mutation arguments.
			existing[strings.ToLower(name)] = true
		}
	}
	return existing, nil
}

func ensurePrintBridgeSharing(ctx context.Context, runner CommandRunner, config HelperConfig) error {
	cupsConfigPath := config.CUPSConfigPath
	if cupsConfigPath == "" {
		cupsConfigPath = "/etc/cups/cupsd.conf"
	}
	policyEnabled, err := socketActivatedCUPSSharingConfigured(cupsConfigPath)
	if err != nil {
		return err
	}
	sharingChanged := false
	if !policyEnabled {
		settings, runErr := runner.Run(ctx, "/usr/sbin/cupsctl", []string{})
		if runErr != nil {
			return runErr
		}
		if !cupsSharingEnabled(settings) {
			if _, runErr = runner.Run(ctx, "/usr/sbin/cupsctl", []string{"--share-printers"}); runErr != nil {
				return runErr
			}
			sharingChanged = true
		}
	}
	configChanged, err := normalizeSocketActivatedCUPSConfig(cupsConfigPath)
	if err != nil {
		return err
	}
	if sharingChanged || configChanged {
		if _, err := runner.Run(ctx, "/usr/bin/systemctl", []string{"restart", "cups.socket", "cups.path", "cups.service"}); err != nil {
			return err
		}
	}
	return waitForCUPS(ctx, runner)
}

func directOptionAllowed(name string) bool {
	switch name {
	case "PageSize", "Resolution", "zeMediaTracking", "MediaType", "zePrintMode", "Darkness", "zePrintRate", "zeLabelTop", "zeTearOffPosition":
		return true
	default:
		return false
	}
}
func customMediaAdvertised(media CustomMedia, ppdDir, queueName string) bool {
	if ppdDir == "" {
		ppdDir = "/etc/cups/ppd"
	}
	if bounds, ok := loadPPDBounds(ppdDir, queueName); ok {
		widthPoints, heightPoints := media.Width*72/25.4, media.Height*72/25.4
		return widthPoints >= bounds.MinWidthPoints-0.01 && widthPoints <= bounds.MaxWidthPoints+0.01 && heightPoints >= bounds.MinHeightPoints-0.01 && heightPoints <= bounds.MaxHeightPoints+0.01
	}
	return false
}

func loadPPDBounds(directory, queueName string) (printer.VariablePaperBounds, bool) {
	data, err := readQueuePPD(directory, queueName)
	if err != nil {
		return printer.VariablePaperBounds{}, false
	}
	return printer.ParseVariablePaperBounds(data)
}

func readQueuePPD(directory, queueName string) ([]byte, error) {
	if directory == "" {
		directory = "/etc/cups/ppd"
	}
	if !safeQueueName(queueName) || filepath.Base(queueName) != queueName || strings.Contains(directory, "..") {
		return nil, errors.New("cups reconcile: unsafe PPD path")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	filename := ""
	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), queueName+".ppd") {
			continue
		}
		if filename != "" {
			return nil, errors.New("cups reconcile: ambiguous PPD name")
		}
		filename = entry.Name()
	}
	if filename == "" {
		return nil, os.ErrNotExist
	}
	return readPPD(filepath.Join(directory, filename))
}

func readPPD(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > printer.MaxPPDBytes || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("cups reconcile: unsafe PPD")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (os.Geteuid() == 0 && stat.Uid != 0) {
		return nil, errors.New("cups reconcile: unsafe PPD owner")
	}
	return os.ReadFile(path)
}
func formatMM(value float64) string { return strconv.FormatFloat(value, 'f', -1, 64) }

func loadHelperRequest(path string) (HelperRequest, error) {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return HelperRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request HelperRequest
	if err := decoder.Decode(&request); err != nil {
		return HelperRequest{}, errors.New("cups reconcile: malformed helper request")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return HelperRequest{}, errors.New("cups reconcile: malformed helper request")
	}
	desired := Desired{DefaultQueue: request.DefaultQueue, Version: request.Version, Type: DesiredType, SessionID: "helper", DeviceID: "helper", DesiredHash: request.DesiredHash, Queues: request.Queues}
	if request.Type != "printer.helper.request" || desired.Validate() != nil {
		return HelperRequest{}, errors.New("cups reconcile: invalid helper request")
	}
	request.Queues = desired.Normalize().Queues
	return request, nil
}

func applyQueues(ctx context.Context, runner CommandRunner, config HelperConfig, request HelperRequest) error {
	if err := waitForCUPS(ctx, runner); err != nil {
		return err
	}
	manifestPath := filepath.Join(config.ManifestDir, config.Profile+".json")
	previous := loadManifest(manifestPath)
	desiredRemote := make(map[string]string)
	previousOwned := make(map[string]string, len(previous.Queues)+len(previous.Claims))
	for _, name := range append(append([]string(nil), previous.Queues...), previous.Claims...) {
		if safeDirectQueueName(name) && previousOwned[strings.ToLower(name)] == "" {
			previousOwned[strings.ToLower(name)] = name
		}
	}
	claimNames := make([]string, 0, len(request.Queues))
	for _, queue := range request.Queues {
		if queue.Mode != ModeRemote {
			continue
		}
		if !safeDirectQueueName(queue.LocalName) || !safeRemoteURI(queue.RemoteURI) || len(queue.Options) != 0 {
			return errors.New("cups reconcile: invalid remote queue")
		}
		folded := strings.ToLower(queue.LocalName)
		if _, duplicate := desiredRemote[folded]; duplicate {
			return errors.New("cups reconcile: duplicate remote queue")
		}
		desiredRemote[folded] = queue.LocalName
		claimNames = append(claimNames, queue.LocalName)
	}
	var existing map[string]bool
	if len(claimNames) > 0 || len(previousOwned) > 0 || len(previous.Settings) > 0 {
		var err error
		existing, err = enumerateCUPSQueues(ctx, runner)
		if err != nil {
			return err
		}
		for folded := range desiredRemote {
			if _, owned := previousOwned[folded]; existing[folded] && !owned {
				return errors.New("cups reconcile: refusing unmanaged remote queue")
			}
		}
	}
	if len(claimNames) > 0 {
		if err := stageOwnedClaims(config, manifestPath, &previous, Version, claimNames); err != nil {
			return err
		}
	}
	desiredSettings := make(map[string][]string)
	if config.Profile == "print-bridge" && len(request.Queues) > 0 {
		if err := ensurePrintBridgeSharing(ctx, runner, config); err != nil {
			return err
		}
	}

	for _, queue := range request.Queues {
		switch queue.Mode {
		case ModeRemote:
			args := []string{"-p", queue.LocalName, "-E", "-v", queue.RemoteURI, "-m", "everywhere", "-o", "printer-is-shared=false"}
			if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", args); err != nil {
				return err
			}
			existing[strings.ToLower(queue.LocalName)] = true
			if err := waitForCUPS(ctx, runner); err != nil {
				return err
			}
		case ModeExisting:
			args := []string{"-p", queue.LocalName}
			var advertised []printer.QueueOption
			if len(queue.Options) > 0 || len(previous.Settings[settingsQueueName(previous, queue.LocalName)]) > 0 && existing[strings.ToLower(queue.LocalName)] {
				var err error
				advertised, err = readAdvertisedOptions(ctx, runner, queue.LocalName)
				if err != nil || !existingOptionsAdvertised(queue.Options, advertised, config.PPDDir, queue.LocalName) {
					return errors.New("cups reconcile: desired option is not advertised")
				}
			}
			optionNames := make([]string, 0, len(queue.Options))
			for _, option := range queue.Options {
				args = append(args, "-o", option.Name+"="+option.Value)
				optionNames = append(optionNames, option.Name)
			}
			if err := stageOwnedSettings(config, manifestPath, &previous, Version, queue.LocalName, optionNames, advertised); err != nil {
				return err
			}
			if existing[strings.ToLower(queue.LocalName)] {
				restore, err := restoreOwnedOptions(config, previous, queue.LocalName, optionNames, advertised)
				if err != nil {
					return err
				}
				for _, option := range restore {
					args = append(args, "-o", option.Name+"="+option.Value)
				}
			}
			sort.Strings(optionNames)
			desiredSettings[settingsQueueName(previous, queue.LocalName)] = optionNames
			if len(args) > 2 {
				if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", args); err != nil {
					return err
				}
				if err := waitForCUPS(ctx, runner); err != nil {
					return err
				}
			}
		}
	}
	for queueName, optionNames := range previous.Settings {
		if _, present := desiredSettings[queueName]; present || len(optionNames) == 0 || !existing[strings.ToLower(queueName)] {
			continue
		}
		advertised, err := readAdvertisedOptions(ctx, runner, queueName)
		if err != nil {
			return err
		}
		restore, err := restoreOwnedOptions(config, previous, queueName, nil, advertised)
		if err != nil {
			return err
		}
		args := []string{"-p", queueName}
		for _, option := range restore {
			args = append(args, "-o", option.Name+"="+option.Value)
		}
		if len(args) > 2 {
			if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", args); err != nil {
				return err
			}
			if err := waitForCUPS(ctx, runner); err != nil {
				return err
			}
		}
	}
	obsolete := make([]string, 0, len(previousOwned))
	for _, name := range previousOwned {
		obsolete = append(obsolete, name)
	}
	sort.Strings(obsolete)
	for _, name := range obsolete {
		if _, keep := desiredRemote[strings.ToLower(name)]; keep || !existing[strings.ToLower(name)] {
			continue
		}
		if _, err := runner.Run(ctx, "/usr/sbin/lpadmin", []string{"-x", name}); err != nil {
			return err
		}
		delete(existing, strings.ToLower(name))
		if err := waitForCUPS(ctx, runner); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(desiredRemote))
	for _, name := range desiredRemote {
		names = append(names, name)
	}
	sort.Strings(names)
	return writeRootAtomic(config.ManifestDir, manifestPath, mustMarshal(ownedManifest{Version: Version, Queues: names, Settings: desiredSettings, Defaults: retainedDefaults(previous.Defaults, desiredSettings)}), -1, -1)
}

func socketActivatedCUPSSharingConfigured(path string) (bool, error) {
	data, err := readCUPSConfig(path)
	if err != nil {
		return false, err
	}
	listen, browsing, allowLocal, port := 0, 0, 0, 0
	for line := range strings.SplitSeq(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		switch strings.TrimSpace(line) {
		case "Listen localhost:631":
			listen++
		case "Browsing On", "Browsing Yes":
			browsing++
		case "Allow @LOCAL":
			allowLocal++
		case "Port 631":
			port++
		}
	}
	return listen == 1 && browsing == 1 && allowLocal >= 1 && port == 0, nil
}

func readCUPSConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128*1024 {
		return nil, errors.New("cups reconcile: unsafe CUPS configuration")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (os.Geteuid() == 0 && stat.Uid != 0) {
		return nil, errors.New("cups reconcile: unsafe CUPS configuration owner")
	}
	return os.ReadFile(path)
}

func cupsSharingEnabled(output []byte) bool {
	for line := range strings.SplitSeq(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "_share_printers=1" {
			return true
		}
	}
	return false
}

func normalizeSocketActivatedCUPSConfig(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128*1024 {
		return false, errors.New("cups reconcile: unsafe CUPS configuration")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (os.Geteuid() == 0 && stat.Uid != 0) {
		return false, errors.New("cups reconcile: unsafe CUPS configuration owner")
	}
	data, err := readCUPSConfig(path)
	if err != nil {
		return false, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	portCount := 0
	listenCount := 0
	for index, line := range lines {
		switch strings.TrimSpace(line) {
		case "Port 631":
			portCount++
			lines[index] = "Listen localhost:631"
		case "Listen localhost:631":
			listenCount++
		}
	}
	if portCount == 0 {
		if listenCount == 1 {
			return false, nil
		}
		return false, errors.New("cups reconcile: expected CUPS listener directive is missing")
	}
	if portCount != 1 || listenCount != 0 {
		return false, errors.New("cups reconcile: ambiguous CUPS listener directives")
	}
	encoded := []byte(strings.Join(lines, "\n"))
	directory := filepath.Dir(path)
	if err := writeRootAtomic(directory, path, encoded, int(stat.Uid), int(stat.Gid)); err != nil {
		return false, err
	}
	if err := os.Chmod(path, info.Mode().Perm()); err != nil {
		return false, err
	}
	return true, nil
}

func waitForCUPS(ctx context.Context, runner CommandRunner) error {
	for range 20 {
		if _, err := runner.Run(ctx, "/usr/bin/lpstat", []string{"-r"}); err == nil {
			return nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("cups reconcile: scheduler unavailable")
}

func optionsAdvertised(desired []Option, advertised []printer.QueueOption) bool {
	available := make(map[string]map[string]struct{}, len(advertised))
	for _, option := range advertised {
		choices := make(map[string]struct{}, len(option.Choices))
		for _, choice := range option.Choices {
			choices[choice] = struct{}{}
		}
		available[option.Name] = choices
	}
	for _, option := range desired {
		choices := available[option.Name]
		if _, present := choices[option.Value]; !present {
			return false
		}
	}
	return true
}

var customPageSizePattern = regexp.MustCompile(`^Custom\.([1-9][0-9]{0,2}(?:\.[0-9]{1,2})?)x([1-9][0-9]{0,3}(?:\.[0-9]{1,2})?)mm$`)

func parseCustomPageSize(value string) (CustomMedia, bool) {
	match := customPageSizePattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return CustomMedia{}, false
	}
	width, widthErr := strconv.ParseFloat(match[1], 64)
	height, heightErr := strconv.ParseFloat(match[2], 64)
	media := CustomMedia{Width: width, Height: height, Unit: "mm"}
	return media, widthErr == nil && heightErr == nil && validCustomMedia(media)
}

func existingOptionsAdvertised(desired []Option, advertised []printer.QueueOption, ppdDir, queueName string) bool {
	for _, option := range desired {
		media, custom := parseCustomPageSize(option.Value)
		if option.Name == "PageSize" && custom {
			if !optionsAdvertised([]Option{{Name: "PageSize", Value: "Custom.WIDTHxHEIGHT"}}, advertised) || !customMediaAdvertised(media, ppdDir, queueName) {
				return false
			}
			continue
		}
		if !optionsAdvertised([]Option{option}, advertised) {
			return false
		}
	}
	return true
}

func loadManifest(path string) ownedManifest {
	data, err := readBoundedRegular(path, MaxMessageBytes)
	if err != nil {
		return ownedManifest{Version: Version, Queues: []string{}, Settings: map[string][]string{}}
	}
	var manifest ownedManifest
	if json.Unmarshal(data, &manifest) != nil || (manifest.Version != Version && manifest.Version != Version2) {
		return ownedManifest{Version: Version, Queues: []string{}, Settings: map[string][]string{}}
	}
	if manifest.Settings == nil {
		manifest.Settings = map[string][]string{}
	}
	return manifest
}

func writeHelperResult(stateDir string, result HelperResult) error {
	info, err := os.Stat(stateDir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cups reconcile: state owner unavailable")
	}
	uid, gid := -1, -1
	if os.Geteuid() == 0 {
		uid, gid = int(stat.Uid), int(stat.Gid)
	}
	return writeRootAtomic(stateDir, filepath.Join(stateDir, HelperResultName), mustMarshal(result), uid, gid)
}

func writeRootAtomic(directory, path string, data []byte, uid, gid int) error {
	temporary, err := os.CreateTemp(directory, ".cups-helper-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := temporary.Chown(uid, gid); err != nil {
			temporary.Close()
			return err
		}
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

func mustMarshal(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
