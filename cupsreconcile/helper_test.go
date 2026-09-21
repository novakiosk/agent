package cupsreconcile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/novakiosk/agent/printer"
)

type helperRunner struct {
	queues         map[string]bool
	calls          [][]string
	sharingEnabled bool
}

type directRunner struct {
	calls     [][]string
	existing  map[string]bool
	failed    bool
	failQueue string
}

func (runner *directRunner) Run(_ context.Context, path string, args []string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string{path}, args...))
	if path == "/usr/bin/lpstat" && len(args) == 1 && args[0] == "-r" {
		return []byte("scheduler is running\n"), nil
	}
	if path == "/usr/sbin/cupsctl" && len(args) == 0 {
		return []byte("_share_printers=1\n"), nil
	}
	if path == "/usr/bin/lpstat" && len(args) == 2 && args[0] == "-p" {
		if runner.existing[args[1]] {
			return []byte("printer " + args[1] + " is idle\n"), nil
		}
		return nil, os.ErrNotExist
	}
	if path == "/usr/bin/lpstat" && len(args) == 1 && args[0] == "-e" {
		names := make([]string, 0, len(runner.existing))
		for name, present := range runner.existing {
			if present {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		return []byte(strings.Join(names, "\n")), nil
	}
	if path == "/usr/bin/lpoptions" {
		return []byte("PageSize/Media Size: *A4 Custom.WIDTHxHEIGHT\nResolution/Resolution: *203dpi 300dpi 600dpi\nzeMediaTracking/Tracking: *Web Continuous Mark\nMediaType/Media Type: *Saved Thermal Direct\nzePrintMode/Print Mode: *Cutter Saved Tear Peel Rewind Applicator\n"), nil
	}
	if path == "/usr/sbin/lpadmin" {
		for index, argument := range args {
			if argument == "-x" && index+1 < len(args) {
				delete(runner.existing, args[index+1])
			}
		}
		if runner.failed || (runner.failQueue != "" && len(args) > 1 && args[0] == "-p" && args[1] == runner.failQueue) {
			return nil, errors.New("simulated lpadmin failure")
		}
		if len(args) > 1 && args[0] == "-p" {
			runner.existing[args[1]] = true
		}
		return nil, nil
	}
	return nil, nil
}

func (runner *helperRunner) Run(_ context.Context, path string, args []string) ([]byte, error) {
	runner.calls = append(runner.calls, append([]string{path}, args...))
	if runner.queues == nil {
		runner.queues = make(map[string]bool)
	}
	if path == "/usr/sbin/lpadmin" && len(args) > 1 {
		if args[0] == "-p" {
			runner.queues[args[1]] = true
		}
		if args[0] == "-x" {
			delete(runner.queues, args[1])
		}
	}
	if path == "/usr/bin/lpstat" && slices.Equal(args, []string{"-e"}) {
		names := make([]string, 0, len(runner.queues))
		for name := range runner.queues {
			names = append(names, name)
		}
		slices.Sort(names)
		return []byte(strings.Join(names, "\n")), nil
	}
	if path == "/usr/sbin/cupsctl" && len(args) == 0 {
		if runner.sharingEnabled {
			return []byte("_share_printers=1\n_remote_any=0\n"), nil
		}
		return []byte("_share_printers=0\n_remote_any=0\n"), nil
	}
	if path == "/usr/bin/lpoptions" {
		return []byte("PageSize/Media Size: 2x1 *4x6 Custom.WIDTHxHEIGHT\n"), nil
	}
	return nil, nil
}

func writeHelperRequest(t *testing.T, stateDir string, desired Desired) {
	t.Helper()
	request := HelperRequest{Version: Version, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Normalize().Queues}
	if err := saveUserAtomic(stateDir, filepath.Join(stateDir, HelperRequestName), mustMarshal(request)); err != nil {
		t.Fatal(err)
	}
}

func writeCUPSConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cupsd.conf")
	if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHelperUsesFixedArgvAndRemovesOnlyManifestOwnedState(t *testing.T) {
	stateDir := t.TempDir()
	manifestDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &helperRunner{}
	desired := testDesired(t)
	writeHelperRequest(t, stateDir, desired)
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "kiosk", Runner: runner}); err != nil {
		t.Fatal(err)
	}
	wantFirst := [][]string{
		{"/usr/bin/lpstat", "-r"},
		{"/usr/bin/lpstat", "-e"},
		{"/usr/bin/lpoptions", "-p", "usb", "-l"},
		{"/usr/sbin/lpadmin", "-p", "usb", "-o", "PageSize=4x6"},
		{"/usr/bin/lpstat", "-r"},
		{"/usr/sbin/lpadmin", "-p", "NOVA_wireless", "-E", "-v", "ipps://print.local:631/printers/wireless", "-m", "everywhere", "-o", "printer-is-shared=false"},
		{"/usr/bin/lpstat", "-r"},
	}
	if !reflect.DeepEqual(runner.calls, wantFirst) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, wantFirst)
	}
	result, err := loadHelperResult(filepath.Join(stateDir, HelperResultName), desired.DesiredHash)
	if err != nil || result.Result != ResultApplied {
		t.Fatalf("result = %+v, %v", result, err)
	}

	empty := Desired{Version: Version, Type: DesiredType, SessionID: "session-1", DeviceID: "device-1", Queues: []Queue{}}
	empty.DesiredHash, _ = empty.PayloadHash()
	writeHelperRequest(t, stateDir, empty)
	manifestPath := filepath.Join(manifestDir, "kiosk.json")
	if err := writeRootAtomic(manifestDir, manifestPath, mustMarshal(ownedManifest{Version: Version, Queues: []string{"NOVA_wireless", "OfficeQueue"}, Settings: map[string][]string{"usb": {"PageSize"}}, Defaults: map[string]map[string]string{"usb": {"PageSize": "4x6"}}}), -1, -1); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "kiosk", Runner: runner}); err != nil {
		t.Fatal(err)
	}
	wantSecond := [][]string{
		{"/usr/bin/lpstat", "-r"},
		{"/usr/bin/lpstat", "-e"},
		{"/usr/bin/lpoptions", "-p", "usb", "-l"},
		{"/usr/sbin/lpadmin", "-p", "usb", "-o", "PageSize=4x6"},
		{"/usr/bin/lpstat", "-r"},
		{"/usr/sbin/lpadmin", "-x", "NOVA_wireless"},
		{"/usr/bin/lpstat", "-r"},
	}
	if !reflect.DeepEqual(runner.calls, wantSecond) {
		t.Fatalf("cleanup calls = %#v, want %#v", runner.calls, wantSecond)
	}
}

func TestHelperRejectsUnadvertisedOptionWithoutLpadmin(t *testing.T) {
	stateDir := t.TempDir()
	manifestDir := t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	desired := testDesired(t)
	desired.Queues[1].Options[0].Value = "not-advertised"
	desired.DesiredHash, _ = desired.PayloadHash()
	writeHelperRequest(t, stateDir, desired)
	runner := &helperRunner{}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "kiosk", Runner: runner}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call[0] == "/usr/sbin/lpadmin" && strings.Contains(strings.Join(call, " "), "not-advertised") {
			t.Fatalf("unsafe option reached lpadmin: %v", call)
		}
	}
	result, err := loadHelperResult(filepath.Join(stateDir, HelperResultName), desired.DesiredHash)
	if err != nil || result.Result != ResultFailed || result.ErrorCategory != ErrorApply {
		t.Fatalf("result = %+v, %v", result, err)
	}
}

func TestHelperAppliesBoundedCustomMediaToExistingUSBQueue(t *testing.T) {
	stateDir, manifestDir, ppdDir := t.TempDir(), t.TempDir(), t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	desired := Desired{Version: Version, Type: DesiredType, SessionID: "session-1", DeviceID: "device-1", Queues: []Queue{{PrinterID: "printer-usb", LocalName: "usb", Mode: ModeExisting, Options: []Option{{Name: "PageSize", Value: "Custom.90x70mm"}}}}}
	desired.DesiredHash, _ = desired.PayloadHash()
	writeHelperRequest(t, stateDir, desired)
	if err := os.WriteFile(filepath.Join(ppdDir, "usb.ppd"), []byte("*CustomPageSize True\n*DefaultPageSize: Custom.90x70mm\n*ParamCustomPageSize Width: 1 points 36 576\n*ParamCustomPageSize Height: 2 points 36 3600\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	runner := &helperRunner{}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "kiosk", Runner: runner, PPDDir: ppdDir}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(flattenCalls(runner.calls), "\n"), "/usr/sbin/lpadmin -p usb -o PageSize=Custom.90x70mm") {
		t.Fatalf("custom media was not applied: %#v", runner.calls)
	}

	desired.Queues[0].Options[0].Value = "Custom.300x70mm"
	desired.DesiredHash, _ = desired.PayloadHash()
	writeHelperRequest(t, stateDir, desired)
	runner.calls = nil
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "kiosk", Runner: runner, PPDDir: ppdDir}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call[0] == "/usr/sbin/lpadmin" {
			t.Fatalf("out-of-range media reached lpadmin: %v", call)
		}
	}
}

func TestPrintBridgeHelperEnablesOnlyLocalSubnetSharing(t *testing.T) {
	stateDir := t.TempDir()
	manifestDir := t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	desired := Desired{Version: Version, Type: DesiredType, SessionID: "session-1", DeviceID: "device-1", Queues: []Queue{{PrinterID: "printer-a", LocalName: "wireless", Mode: ModeExisting, Options: []Option{{Name: "PageSize", Value: "4x6"}}}}}
	desired.DesiredHash, _ = desired.PayloadHash()
	writeHelperRequest(t, stateDir, desired)
	runner := &helperRunner{}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "print-bridge", Runner: runner, CUPSConfigPath: writeCUPSConfig(t, "Port 631\nListen /run/cups/cups.sock\n")}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/usr/bin/lpstat", "-r"},
		{"/usr/sbin/cupsctl"},
		{"/usr/sbin/cupsctl", "--share-printers"},
		{"/usr/bin/systemctl", "restart", "cups.socket", "cups.path", "cups.service"},
		{"/usr/bin/lpstat", "-r"},
		{"/usr/bin/lpoptions", "-p", "wireless", "-l"},
		{"/usr/sbin/lpadmin", "-p", "wireless", "-o", "PageSize=4x6"},
		{"/usr/bin/lpstat", "-r"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestPrintBridgeHelperDoesNotRestartAlreadyEnabledSharing(t *testing.T) {
	stateDir := t.TempDir()
	manifestDir := t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	desired := Desired{Version: Version, Type: DesiredType, SessionID: "session-1", DeviceID: "device-1", Queues: []Queue{{PrinterID: "printer-a", LocalName: "wireless", Mode: ModeExisting, Options: []Option{}}}}
	desired.DesiredHash, _ = desired.PayloadHash()
	writeHelperRequest(t, stateDir, desired)
	runner := &helperRunner{sharingEnabled: true}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "print-bridge", Runner: runner, CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nListen /run/cups/cups.sock\nBrowsing On\n<Location />\n  Allow @LOCAL\n</Location>\n")}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/usr/bin/lpstat", "-r"}, {"/usr/bin/lpstat", "-r"}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestDirectHelperDerivesFixedZebraArgvAndCustomMedia(t *testing.T) {
	stateDir, manifestDir, ppdDir := t.TempDir(), t.TempDir(), t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	queue := Queue{PrinterID: "printer-a", LocalName: "NOVA_ZEBRA_WIRELESS_1", Mode: ModeDirect, PrivateIP: "192.168.102.250", ConnectionProfile: ConnectionZebraAppSocket, DriverProfile: DriverZebraZPL, DisplayName: "Zebra ZD421 Wireless 1", Location: "Central print server", Options: []Option{{Name: "Resolution", Value: "203dpi"}}, CustomMedia: &CustomMedia{Width: 90, Height: 65, Unit: "mm"}}
	desired := DesiredV2{Version: Version2, Type: DesiredType, SessionID: "session", DeviceID: "bridge", Queues: []Queue{queue}}
	desired.DesiredHash, _ = desired.PayloadHash()
	request := HelperRequestV2{Version: Version2, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Queues}
	if err := saveUserAtomic(stateDir, filepath.Join(stateDir, HelperRequestName), mustMarshal(request)); err != nil {
		t.Fatal(err)
	}
	ppd := []byte("*CustomPageSize True\n*ParamCustomPageSize Width: 1 points 36 576\n*ParamCustomPageSize Height: 2 points 36 3600\n")
	ppd = append(ppd, bytes.Repeat([]byte("*% padding\n"), 26_000)...)
	if err := os.WriteFile(filepath.Join(ppdDir, queue.LocalName+".ppd"), ppd, 0o640); err != nil {
		t.Fatal(err)
	}
	cupsConfig := writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")
	runner := &directRunner{existing: map[string]bool{}}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "print-bridge", Runner: runner, CUPSConfigPath: cupsConfig, PPDDir: ppdDir}); err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, call := range runner.calls {
		joined += strings.Join(call, " ") + "\n"
	}
	for _, fragment := range []string{"/usr/sbin/lpadmin -p NOVA_ZEBRA_WIRELESS_1 -E -v socket://192.168.102.250:9100 -m drv:///sample.drv/zebra.ppd", "-o printer-is-shared=true", "PageSize=Custom.90x65mm"} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("fixed direct argv missing %q in:\n%s", fragment, joined)
		}
	}
	result, err := loadHelperResultV2(filepath.Join(stateDir, HelperResultName), desired.DesiredHash)
	if err != nil || result.Version != Version2 || result.Result != ResultApplied {
		t.Fatalf("result = %+v, %v", result, err)
	}
	manifest := loadManifest(filepath.Join(manifestDir, "print-bridge.json"))
	if manifest.Version != Version2 || !slices.Contains(manifest.Queues, queue.LocalName) || !slices.Contains(manifest.Settings[queue.LocalName], "PageSize") {
		t.Fatalf("direct manifest = %+v", manifest)
	}
	runner.calls = nil
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "print-bridge", Runner: runner, CUPSConfigPath: cupsConfig, PPDDir: ppdDir}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(flattenCalls(runner.calls), "\n"), "-m drv:///sample.drv/zebra.ppd") {
		t.Fatalf("idempotent retry did not reapply fixed driver: %#v", runner.calls)
	}
}

func TestDirectHelperValidatesOwnedQueueBeforeMutation(t *testing.T) {
	stateDir, manifestDir := t.TempDir(), t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	queue := Queue{PrinterID: "printer-a", LocalName: "NOVA_ZEBRA_WIRELESS_1", Mode: ModeDirect, PrivateIP: "192.168.102.250", ConnectionProfile: ConnectionZebraAppSocket, DriverProfile: DriverZebraZPL, DisplayName: "Zebra ZD421 Wireless 1", Location: "Central print server", Options: []Option{{Name: "Resolution", Value: "1200dpi"}}}
	desired := DesiredV2{Version: Version2, Type: DesiredType, SessionID: "session", DeviceID: "bridge", Queues: []Queue{queue}}
	desired.DesiredHash, _ = desired.PayloadHash()
	request := HelperRequestV2{Version: Version2, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Queues}
	if err := saveUserAtomic(stateDir, filepath.Join(stateDir, HelperRequestName), mustMarshal(request)); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDir, "print-bridge.json")
	if err := writeRootAtomic(manifestDir, manifestPath, mustMarshal(ownedManifest{Version: Version2, Queues: []string{queue.LocalName}, Settings: map[string][]string{queue.LocalName: {"Resolution"}}}), -1, -1); err != nil {
		t.Fatal(err)
	}
	runner := &directRunner{existing: map[string]bool{queue.LocalName: true}}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "print-bridge", Runner: runner, CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call[0] == "/usr/sbin/lpadmin" {
			t.Fatalf("invalid edit mutated owned queue: %v", call)
		}
	}
	result, err := loadHelperResultV2(filepath.Join(stateDir, HelperResultName), desired.DesiredHash)
	if err != nil || result.Result != ResultFailed {
		t.Fatalf("invalid edit result = %+v, %v", result, err)
	}
}

func flattenCalls(calls [][]string) []string {
	flattened := make([]string, 0, len(calls))
	for _, call := range calls {
		flattened = append(flattened, strings.Join(call, " "))
	}
	return flattened
}

func TestDirectDesiredCannotRunOnKioskProfile(t *testing.T) {
	stateDir, manifestDir := t.TempDir(), t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	desired := DesiredV2{Version: Version2, Type: DesiredType, SessionID: "session", DeviceID: "bridge", Queues: []Queue{{PrinterID: "p", LocalName: "NOVA_P", Mode: ModeDirect, PrivateIP: "10.0.0.4", ConnectionProfile: ConnectionZebraAppSocket, DriverProfile: DriverZebraZPL, DisplayName: "Zebra", Location: "Room"}}}
	desired.DesiredHash, _ = desired.PayloadHash()
	if err := saveUserAtomic(stateDir, filepath.Join(stateDir, HelperRequestName), mustMarshal(HelperRequestV2{Version: Version2, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Queues})); err != nil {
		t.Fatal(err)
	}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "kiosk", Runner: &directRunner{existing: map[string]bool{}}}); err == nil {
		t.Fatal("kiosk helper accepted direct v2 request")
	}
}

func TestDirectHelperRefusesUnownedCollisionBeforeManifestClaim(t *testing.T) {
	stateDir, manifestDir, ppdDir := t.TempDir(), t.TempDir(), t.TempDir()
	_ = os.Chmod(stateDir, 0o700)
	queue := Queue{PrinterID: "printer-a", LocalName: "NOVA_COLLISION", Mode: ModeDirect, PrivateIP: "10.0.0.4", ConnectionProfile: ConnectionZebraAppSocket, DriverProfile: DriverZebraZPL, DisplayName: "Zebra", Location: "Room", Options: []Option{}}
	desired := DesiredV2{Version: Version2, Type: DesiredType, SessionID: "session", DeviceID: "bridge", Queues: []Queue{queue}}
	desired.DesiredHash, _ = desired.PayloadHash()
	if err := saveUserAtomic(stateDir, filepath.Join(stateDir, HelperRequestName), mustMarshal(HelperRequestV2{Version: Version2, Type: "printer.helper.request", DesiredHash: desired.DesiredHash, Queues: desired.Queues})); err != nil {
		t.Fatal(err)
	}
	runner := &directRunner{existing: map[string]bool{queue.LocalName: true}}
	if err := ApplyHelper(context.Background(), HelperConfig{StateDir: stateDir, ManifestDir: manifestDir, Profile: "print-bridge", Runner: runner, CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n"), PPDDir: ppdDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(manifestDir, "print-bridge.json")); !os.IsNotExist(err) {
		t.Fatalf("collision changed manifest, stat err=%v", err)
	}
	result, err := loadHelperResultV2(filepath.Join(stateDir, HelperResultName), desired.DesiredHash)
	if err != nil || result.Result != ResultFailed {
		t.Fatalf("collision result = %+v, %v", result, err)
	}
}

type legacyCleanupRunner struct {
	cancelAfterDelete context.CancelFunc
	readinessFailed   bool
	queues            map[string]bool
	deleted           []string
	failDelete        string
	enumerationError  error
	oversized         bool
}

func (r *legacyCleanupRunner) Run(_ context.Context, path string, args []string) ([]byte, error) {
	if path == "/usr/bin/lpstat" && slices.Equal(args, []string{"-r"}) {
		if r.readinessFailed {
			return nil, errors.New("scheduler unavailable")
		}
		return []byte("scheduler is running\n"), nil
	}
	if path == "/usr/bin/lpstat" && slices.Equal(args, []string{"-e"}) {
		if r.enumerationError != nil {
			return nil, r.enumerationError
		}
		if r.oversized {
			return []byte(strings.Repeat("X", MaxMessageBytes+1)), nil
		}
		names := make([]string, 0, len(r.queues))
		for name := range r.queues {
			names = append(names, name)
		}
		slices.Sort(names)
		return []byte(strings.Join(names, "\n")), nil
	}
	if path == "/usr/sbin/lpadmin" && len(args) == 2 && args[0] == "-x" {
		folded := strings.ToLower(args[1])
		if !r.queues[folded] {
			return nil, os.ErrNotExist
		}
		if args[1] == r.failDelete {
			r.failDelete = ""
			return nil, errors.New("transient delete failure")
		}
		delete(r.queues, folded)
		r.deleted = append(r.deleted, args[1])
		if r.cancelAfterDelete != nil {
			r.readinessFailed = true
			r.cancelAfterDelete()
		}
		return nil, nil
	}
	if path == "/usr/sbin/lpadmin" && len(args) > 2 && args[0] == "-p" && args[2] == "-E" {
		r.queues[strings.ToLower(args[1])] = true
		return nil, nil
	}
	return nil, errors.New("unexpected command: " + path + " " + strings.Join(args, " "))
}

func TestLegacyCleanupRetriesPartialDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kiosk.json")
	original := mustMarshal(ownedManifest{Version: Version, Queues: []string{"NOVA_A", "NOVA_B"}, Settings: map[string][]string{}})
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	runner := &legacyCleanupRunner{queues: map[string]bool{"nova_a": true, "nova_b": true, "office@lab": true, "officequeue": true}, failDelete: "NOVA_B"}
	config := HelperConfig{ManifestDir: dir, Profile: "kiosk"}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: "OfficeQueue"}}}
	if err := applyQueues(context.Background(), runner, config, request); err == nil {
		t.Fatal("expected transient cleanup failure")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) || !slices.Equal(runner.deleted, []string{"NOVA_A"}) {
		t.Fatalf("partial failure lost manifest or setup invalid: %v %v", err, runner.deleted)
	}
	if err := applyQueues(context.Background(), runner, config, request); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if !slices.Equal(runner.deleted, []string{"NOVA_A", "NOVA_B"}) || !runner.queues["office@lab"] || len(loadManifest(path).Queues) != 0 {
		t.Fatalf("cleanup incomplete or unmanaged queue mutated: %v %+v", runner.deleted, runner.queues)
	}
}

func TestLegacyCleanupEnumerationFailurePreservesManifest(t *testing.T) {
	for _, kind := range []string{"failed", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kiosk.json")
			original := mustMarshal(ownedManifest{Version: Version, Queues: []string{"NOVA_A"}, Settings: map[string][]string{}})
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			runner := &legacyCleanupRunner{queues: map[string]bool{"nova_a": true}, oversized: kind == "oversized"}
			if kind == "failed" {
				runner.enumerationError = errors.New("query failed")
			}
			if err := applyQueues(context.Background(), runner, HelperConfig{ManifestDir: dir, Profile: "kiosk"}, HelperRequest{Version: Version}); err == nil {
				t.Fatal("invalid enumeration accepted")
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, original) || len(runner.deleted) != 0 {
				t.Fatal("failed enumeration changed manifest or deleted queue")
			}
		})
	}
}

func TestLegacyCleanupRetriesAfterLastDeleteReadinessFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kiosk.json")
	original := mustMarshal(ownedManifest{Version: Version, Queues: []string{"NOVA_A"}, Settings: map[string][]string{}})
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &legacyCleanupRunner{queues: map[string]bool{"nova_a": true}, cancelAfterDelete: cancel}
	config := HelperConfig{ManifestDir: dir, Profile: "kiosk"}
	if err := applyQueues(ctx, runner, config, HelperRequest{Version: Version}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected interrupted post-delete readiness: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) || len(runner.queues) != 0 {
		t.Fatal("invalid interrupted setup or manifest lost")
	}
	runner.readinessFailed = false
	runner.cancelAfterDelete = nil
	if err := applyQueues(context.Background(), runner, config, HelperRequest{Version: Version}); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if len(loadManifest(path).Queues) != 0 || !slices.Equal(runner.deleted, []string{"NOVA_A"}) {
		t.Fatal("retry did not complete without repeating deletion")
	}
}

func TestLegacyCleanupKeepsDesiredRemoteCaseVariant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kiosk.json")
	previous := ownedManifest{Version: Version, Queues: []string{"NOVA_KEEP", "NOVA_OLD", "NOVA_old"}, Settings: map[string][]string{}}
	if err := os.WriteFile(path, mustMarshal(previous), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &legacyCleanupRunner{queues: map[string]bool{"nova_old": true, "office@lab": true}}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeRemote, LocalName: "NOVA_keep", RemoteURI: "ipps://print.local:631/printers/keep"}}}
	if err := applyQueues(context.Background(), runner, HelperConfig{ManifestDir: dir, Profile: "kiosk"}, request); err != nil {
		t.Fatal(err)
	}
	if !runner.queues["nova_keep"] || !runner.queues["office@lab"] || !slices.Equal(runner.deleted, []string{"NOVA_OLD"}) || !slices.Equal(loadManifest(path).Queues, []string{"NOVA_keep"}) {
		t.Fatalf("desired or unmanaged queue removed: %+v %v", runner.queues, runner.deleted)
	}
}

type defaultTrackingRunner struct {
	defaults     map[string]map[string]string
	advertise    bool
	failMutation bool
}

func (runner *defaultTrackingRunner) Run(_ context.Context, path string, args []string) ([]byte, error) {
	args = slices.Clone(args)
	if len(args) >= 2 && args[0] == "-p" {
		for name := range runner.defaults {
			if strings.EqualFold(name, args[1]) {
				args[1] = name
				break
			}
		}
	}
	if path == "/usr/bin/lpstat" {
		if slices.Equal(args, []string{"-e"}) {
			names := make([]string, 0, len(runner.defaults))
			for name := range runner.defaults {
				names = append(names, name)
			}
			slices.Sort(names)
			return []byte(strings.Join(names, "\n")), nil
		}
		return []byte("scheduler is running\n"), nil
	}
	if path == "/usr/bin/lpoptions" {
		defaults, ok := runner.defaults[args[1]]
		if !ok {
			return nil, os.ErrNotExist
		}
		var output strings.Builder
		for _, item := range []struct {
			name    string
			choices []string
		}{{"PageSize", []string{"A4", "Letter"}}, {"Resolution", []string{"203dpi", "300dpi"}}, {"Darkness", []string{"10", "20"}}} {
			output.WriteString(item.name + "/Label:")
			for _, value := range item.choices {
				output.WriteString(" ")
				if runner.advertise && defaults[item.name] == value {
					output.WriteString("*")
				}
				output.WriteString(value)
			}
			output.WriteString("\n")
		}
		return []byte(output.String()), nil
	}
	if path == "/usr/sbin/lpadmin" && len(args) >= 2 && args[0] == "-p" {
		if runner.failMutation {
			return nil, errors.New("transient mutation failure")
		}
		for index := 2; index+1 < len(args); index++ {
			if args[index] == "-o" {
				name, value, _ := strings.Cut(args[index+1], "=")
				runner.defaults[args[1]][name] = value
			}
		}
		// Like CUPS, -R does not reset a PPD default.
		return nil, nil
	}
	return nil, nil
}

func TestOwnedDefaultsRestoreOriginalAfterUpdates(t *testing.T) {
	runner := &defaultTrackingRunner{advertise: true, defaults: map[string]map[string]string{"a": {"PageSize": "A4", "Resolution": "203dpi", "Darkness": "20"}}}
	config := HelperConfig{ManifestDir: t.TempDir(), Profile: "kiosk"}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: "a", Options: []Option{{Name: "PageSize", Value: "Letter"}, {Name: "Resolution", Value: "300dpi"}}}}}
	if err := applyQueues(context.Background(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	request.Queues[0].Options[0].Value = "A4"
	if err := applyQueues(context.Background(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	request.Queues = nil
	if err := applyQueues(context.Background(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"PageSize": "A4", "Resolution": "203dpi", "Darkness": "20"}
	if !reflect.DeepEqual(runner.defaults["a"], want) {
		t.Fatalf("original PPD defaults not restored: %v", runner.defaults["a"])
	}
}

func TestOwnedDefaultsSurviveQueueCapitalizationChanges(t *testing.T) {
	runner := &defaultTrackingRunner{advertise: true, defaults: map[string]map[string]string{"usb": {"PageSize": "A4"}}}
	config := HelperConfig{ManifestDir: t.TempDir(), Profile: "kiosk"}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: "usb", Options: []Option{{Name: "PageSize", Value: "Letter"}}}}}
	for _, name := range []string{"usb", "USB", "Usb"} {
		request.Queues[0].LocalName = name
		if err := applyQueues(t.Context(), runner, config, request); err != nil {
			t.Fatal(err)
		}
		if got := runner.defaults["usb"]["PageSize"]; got != "Letter" {
			t.Fatalf("queue %s lost desired setting: %s", name, got)
		}
	}
	request.Queues = nil
	if err := applyQueues(t.Context(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	if got := runner.defaults["usb"]["PageSize"]; got != "A4" {
		t.Fatalf("original default lost after case changes: %s", got)
	}
}

func TestDirectDefaultsSurviveQueueCapitalizationChanges(t *testing.T) {
	runner := &defaultTrackingRunner{advertise: true, defaults: map[string]map[string]string{"NOVA_usb": {"Resolution": "203dpi"}}}
	config := HelperConfig{ManifestDir: t.TempDir(), Profile: "print-bridge", CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}
	manifestPath := filepath.Join(config.ManifestDir, "print-bridge.json")
	if err := os.WriteFile(manifestPath, mustMarshal(ownedManifest{Version: Version2, Queues: []string{"NOVA_usb"}}), 0600); err != nil {
		t.Fatal(err)
	}
	request := HelperRequestV2{Queues: []Queue{{Mode: ModeDirect, LocalName: "NOVA_usb", PrivateIP: "192.168.1.50", DisplayName: "Printer", Location: "Test", Options: []Option{{Name: "Resolution", Value: "300dpi"}}}}}
	for _, name := range []string{"NOVA_usb", "NOVA_USB", "NOVA_Usb"} {
		request.Queues[0].LocalName = name
		if err := applyDirectQueues(t.Context(), runner, config, request); err != nil {
			t.Fatal(err)
		}
		if got := runner.defaults["NOVA_usb"]["Resolution"]; got != "300dpi" {
			t.Fatalf("queue %s lost desired setting: %s", name, got)
		}
	}
	request.Queues[0].Options = nil
	if err := applyDirectQueues(t.Context(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	if got := runner.defaults["NOVA_usb"]["Resolution"]; got != "203dpi" {
		t.Fatalf("original default lost after case changes: %s", got)
	}
}

func TestMissingOriginalDefaultFailsBeforeMutation(t *testing.T) {
	runner := &defaultTrackingRunner{defaults: map[string]map[string]string{"a": {"PageSize": "A4"}}}
	config := HelperConfig{ManifestDir: t.TempDir(), Profile: "kiosk"}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: "a", Options: []Option{{Name: "PageSize", Value: "Letter"}}}}}
	if err := applyQueues(context.Background(), runner, config, request); err == nil {
		t.Fatal("missing original default accepted")
	}
	if runner.defaults["a"]["PageSize"] != "A4" || len(loadManifest(filepath.Join(config.ManifestDir, "kiosk.json")).Settings["a"]) != 0 {
		t.Fatal("failed capture acquired ownership or mutated default")
	}
}

func TestLegacyOwnedDefaultIsNeverGuessed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kiosk.json")
	previous := ownedManifest{Version: Version, Settings: map[string][]string{"a": {"PageSize"}}}
	if err := os.WriteFile(path, mustMarshal(previous), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &defaultTrackingRunner{advertise: true, defaults: map[string]map[string]string{"a": {"PageSize": "Letter"}}}
	config := HelperConfig{ManifestDir: dir, Profile: "kiosk"}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: "a", Options: []Option{{Name: "PageSize", Value: "A4"}}}}}
	if err := applyQueues(context.Background(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	request.Queues = nil
	if err := applyQueues(context.Background(), runner, config, request); err == nil {
		t.Fatal("unknown original was guessed or discarded")
	}
	if !slices.Contains(loadManifest(path).Settings["a"], "PageSize") || runner.defaults["a"]["PageSize"] != "A4" {
		t.Fatal("unknown ownership was lost or reset")
	}
}

func TestOwnedDefaultsRestorationFailureRemainsRetryable(t *testing.T) {
	runner := &defaultTrackingRunner{advertise: true, defaults: map[string]map[string]string{"a": {"PageSize": "A4"}, "b": {"PageSize": "A4"}}}
	config := HelperConfig{ManifestDir: t.TempDir(), Profile: "kiosk"}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: "a", Options: []Option{{Name: "PageSize", Value: "Letter"}}}, {Mode: ModeExisting, LocalName: "b", Options: []Option{{Name: "PageSize", Value: "unsupported"}}}}}
	if err := applyQueues(context.Background(), runner, config, request); err == nil {
		t.Fatal("expected later queue failure")
	}
	path := filepath.Join(config.ManifestDir, "kiosk.json")
	if got := loadManifest(path).Defaults["a"]["PageSize"]; got != "A4" {
		t.Fatalf("lost original after partial apply: %q", got)
	}
	request.Queues = nil
	runner.failMutation = true
	if err := applyQueues(context.Background(), runner, config, request); err == nil {
		t.Fatal("failed restoration accepted")
	}
	if got := loadManifest(path).Defaults["a"]["PageSize"]; got != "A4" || runner.defaults["a"]["PageSize"] != "Letter" {
		t.Fatal("failed restoration lost evidence or changed default")
	}
	runner.failMutation = false
	if err := applyQueues(context.Background(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	if runner.defaults["a"]["PageSize"] != "A4" || len(loadManifest(path).Settings) != 0 || len(loadManifest(path).Defaults) != 0 {
		t.Fatal("retry did not restore and retire ownership")
	}
}

func TestStoredOriginalMustRemainAdvertised(t *testing.T) {
	for _, value := range []string{"unsupported", "Custom.WIDTHxHEIGHT", "A4 -x other"} {
		t.Run(value, func(t *testing.T) {
			config := HelperConfig{ManifestDir: t.TempDir(), Profile: "kiosk"}
			path := filepath.Join(config.ManifestDir, "kiosk.json")
			previous := ownedManifest{Version: Version, Settings: map[string][]string{"a": {"PageSize"}}, Defaults: map[string]map[string]string{"a": {"PageSize": value}}}
			if err := os.WriteFile(path, mustMarshal(previous), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &defaultTrackingRunner{advertise: true, defaults: map[string]map[string]string{"a": {"PageSize": "Letter"}}}
			if err := applyQueues(context.Background(), runner, config, HelperRequest{Version: Version}); err == nil {
				t.Fatal("invalid restoration accepted")
			}
			if runner.defaults["a"]["PageSize"] != "Letter" || loadManifest(path).Defaults["a"]["PageSize"] != value {
				t.Fatal("invalid restoration changed defaults or ownership")
			}
		})
	}
}

func TestOriginalCustomDefaultCaptureRequiresConcreteSafePPD(t *testing.T) {
	advertised := printer.ParseQueueOptions([]byte("PageSize/Media: A4 *Custom.WIDTHxHEIGHT\n"))
	for _, test := range []struct {
		name, defaults string
		want           bool
	}{
		{"concrete", "*DefaultPageSize: Custom.90x70mm\n", true},
		{"missing", "", false},
		{"placeholder", "*DefaultPageSize: Custom.WIDTHxHEIGHT\n", false},
		{"duplicate", "*DefaultPageSize: Custom.90x70mm\n*DefaultPageSize: Custom.90x70mm\n", false},
		{"out-of-range", "*DefaultPageSize: Custom.900x70mm\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := HelperConfig{PPDDir: t.TempDir()}
			ppd := test.defaults + "*CustomPageSize True\n*ParamCustomPageSize Width: 1 points 36 576\n*ParamCustomPageSize Height: 2 points 36 3600\n"
			if err := os.WriteFile(filepath.Join(config.PPDDir, "a.ppd"), []byte(ppd), 0640); err != nil {
				t.Fatal(err)
			}
			value, err := captureOptionDefault(config, "a", "PageSize", advertised)
			if (err == nil) != test.want {
				t.Fatalf("capture = %q, %v", value, err)
			}
			if test.want && value != "Custom.90x70mm" {
				t.Fatalf("wrong concrete original: %q", value)
			}
		})
	}
}

func TestQueuePPDResolvesCUPSCaseAlias(t *testing.T) {
	dir := t.TempDir()
	data := []byte("*CustomPageSize True\n*ParamCustomPageSize Width: 1 points 36 576\n*ParamCustomPageSize Height: 2 points 36 3600\n")
	original := filepath.Join(dir, "MixedCase.ppd")
	if err := os.WriteFile(original, data, 0640); err != nil {
		t.Fatal(err)
	}
	if got, err := readQueuePPD(dir, "MIXEDCASE"); err != nil || string(got) != string(data) {
		t.Fatalf("PPD alias lost: %v", err)
	}
	if err := os.Symlink(original, filepath.Join(dir, "mixedcase.ppd")); err != nil {
		t.Fatal(err)
	}
	if _, err := readQueuePPD(dir, "MIXEDCASE"); err == nil {
		t.Fatal("ambiguous PPD accepted")
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if _, err := readQueuePPD(dir, "MIXEDCASE"); err == nil {
		t.Fatal("symlink PPD accepted")
	}
}
