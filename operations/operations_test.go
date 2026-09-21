package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (info fakeInfo) Name() string       { return info.name }
func (info fakeInfo) Size() int64        { return 0 }
func (info fakeInfo) Mode() fs.FileMode  { return info.mode }
func (info fakeInfo) ModTime() time.Time { return time.Time{} }
func (info fakeInfo) IsDir() bool        { return info.mode.IsDir() }
func (info fakeInfo) Sys() any           { return nil }

type fakeEntry struct {
	info fakeInfo
}

func (entry fakeEntry) Name() string               { return entry.info.name }
func (entry fakeEntry) IsDir() bool                { return entry.info.IsDir() }
func (entry fakeEntry) Type() fs.FileMode          { return entry.info.mode }
func (entry fakeEntry) Info() (fs.FileInfo, error) { return entry.info, nil }

type fakeFS struct {
	files   map[string][]byte
	infos   map[string]fakeInfo
	entries map[string][]fs.DirEntry
}

func newFakeFS() *fakeFS {
	return &fakeFS{files: map[string][]byte{}, infos: map[string]fakeInfo{}, entries: map[string][]fs.DirEntry{}}
}

func (filesystem *fakeFS) ReadFile(name string) ([]byte, error) {
	value, ok := filesystem.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}
func (filesystem *fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	value, ok := filesystem.entries[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]fs.DirEntry(nil), value...), nil
}
func (filesystem *fakeFS) Lstat(name string) (fs.FileInfo, error) {
	value, ok := filesystem.infos[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return value, nil
}
func (filesystem *fakeFS) Readlink(name string) (string, error) {
	value, ok := filesystem.files[name+"\x00readlink"]
	if !ok {
		return "", os.ErrInvalid
	}
	return string(value), nil
}

func (filesystem *fakeFS) addFile(name, value string, mode fs.FileMode) {
	filesystem.files[name] = []byte(value)
	filesystem.infos[name] = fakeInfo{name: name, mode: mode}
}
func (filesystem *fakeFS) addDir(name string) {
	filesystem.infos[name] = fakeInfo{name: name, mode: fs.ModeDir | 0755}
}
func (filesystem *fakeFS) addSymlink(name, target string) {
	filesystem.infos[name] = fakeInfo{name: name, mode: fs.ModeSymlink | 0777}
	filesystem.files[name+"\x00readlink"] = []byte(target)
}
func (filesystem *fakeFS) addEntry(directory, name string, mode fs.FileMode) {
	filesystem.entries[directory] = append(filesystem.entries[directory], fakeEntry{info: fakeInfo{name: name, mode: mode}})
}

func inventoryFS() *fakeFS {
	filesystem := newFakeFS()
	filesystem.addFile(BootIDPath, "AABBCCDD-0011-2233-4455-66778899AABB\n", 0644)
	filesystem.addDir(NetClassPath)
	return filesystem
}

func addPhysicalInterface(filesystem *fakeFS, name, mac, state string, target string) {
	interfacePath := NetClassPath + "/" + name
	filesystem.addSymlink(interfacePath, target)
	filesystem.addDir(target)
	filesystem.addSymlink(target+"/device", target+"/device-target")
	filesystem.addDir(target + "/device-target")
	filesystem.addFile(interfacePath+"/address", mac+"\n", 0644)
	filesystem.addFile(interfacePath+"/operstate", state+"\n", 0644)
	filesystem.addEntry(NetClassPath, name, fs.ModeSymlink|0777)
}

func addRegularInterface(filesystem *fakeFS, name, mac, state string) {
	interfacePath := NetClassPath + "/" + name
	filesystem.addDir(interfacePath)
	filesystem.addDir(interfacePath + "/device")
	filesystem.addFile(interfacePath+"/address", mac+"\n", 0644)
	filesystem.addFile(interfacePath+"/operstate", state+"\n", 0644)
	filesystem.addEntry(NetClassPath, name, fs.ModeDir|0755)
}

func TestInventoryFiltersNormalizesAndSortsPhysicalInterfaces(t *testing.T) {
	filesystem := inventoryFS()
	addPhysicalInterface(filesystem, "zeth0", "AA:BB:CC:DD:EE:02", "UP", "/sys/devices/pci/zeth0")
	addPhysicalInterface(filesystem, "aeth0", "aa:bb:cc:dd:ee:01", "down", "/sys/devices/pci/aeth0")
	addPhysicalInterface(filesystem, "wlan0", "aa:bb:cc:dd:ee:03", "up", "/sys/devices/pci/wlan0")
	filesystem.addDir("/sys/devices/pci/wlan0/wireless")
	addRegularInterface(filesystem, "lo", "02:00:00:00:00:01", "up")
	addRegularInterface(filesystem, "novirtual", "00:00:00:00:00:00", "up")
	filesystem.addEntry(NetClassPath, "bad/name", fs.ModeDir|0755)
	filesystem.addSymlink(NetClassPath+"/escape", "/etc")
	filesystem.addEntry(NetClassPath, "escape", fs.ModeSymlink|0777)
	filesystem.addEntry(NetClassPath, "novirtual", fs.ModeDir|0755)
	filesystem.addEntry(NetClassPath, "lo", fs.ModeDir|0755)

	got, err := NewInventoryCollector(InventoryConfig{FS: filesystem}).Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	want := []InterfaceObservation{
		{Name: "aeth0", MAC: "aa:bb:cc:dd:ee:01", OperState: OperStateDown},
		{Name: "zeth0", MAC: "aa:bb:cc:dd:ee:02", OperState: OperStateUp},
	}
	if got.BootID != "aabbccdd-0011-2233-4455-66778899aabb" {
		t.Fatalf("BootID = %q", got.BootID)
	}
	if !reflect.DeepEqual(got.Interfaces, want) {
		t.Fatalf("Interfaces = %#v, want %#v", got.Interfaces, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	encoded, err := json.Marshal(got)
	if err != nil || len(encoded) >= InventoryMaxJSONBytes {
		t.Fatalf("json.Marshal() len=%d err=%v", len(encoded), err)
	}
	if strings.Contains(string(encoded), "address") || strings.Contains(string(encoded), "192.") {
		t.Fatalf("inventory contains unrequested address data: %s", encoded)
	}
}

func TestInventoryPayloadCanonicalizesOrderAndRejectsMalformedValues(t *testing.T) {
	base := Inventory{
		Version: InventoryVersion, Type: InventoryType,
		BootID: "00112233-4455-6677-8899-aabbccddeeff",
		Interfaces: []InterfaceObservation{
			{Name: "zeth0", MAC: "aa:bb:cc:dd:ee:02", OperState: OperStateUnknown},
			{Name: "aeth0", MAC: "aa:bb:cc:dd:ee:01", OperState: OperStateUp},
		},
	}
	reversed := base
	reversed.Interfaces = append([]InterfaceObservation(nil), base.Interfaces...)
	reversed.Interfaces[0], reversed.Interfaces[1] = reversed.Interfaces[1], reversed.Interfaces[0]
	payloadA, err := base.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	payloadB, err := reversed.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payloadA, payloadB) || len(payloadA) == 0 {
		t.Fatalf("canonical payloads differ: %q %q", payloadA, payloadB)
	}
	bad := base
	bad.Interfaces = []InterfaceObservation{{Name: "../escape", MAC: "aa:bb:cc:dd:ee:01", OperState: OperStateUp}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted path traversal interface")
	}
	bad = base
	bad.Interfaces = []InterfaceObservation{{Name: "eth0", MAC: "01:00:00:00:00:01", OperState: OperStateUp}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted multicast MAC")
	}
}

func operationFS() *fakeFS {
	filesystem := newFakeFS()
	filesystem.addFile(BootIDPath, "00112233-4455-6677-8899-aabbccddeeff\n", 0644)
	filesystem.addFile(OstreeBootedPath, "", 0644)
	filesystem.addFile(UpdateUnitPath, "[Service]\n", 0644)
	filesystem.addFile(UpdateHelperPath, "#!/bin/bash\n", 0755)
	filesystem.addFile(RPMOstreePath, "", 0755)
	filesystem.addFile(DefaultSystemctlPath, "", 0755)
	return filesystem
}

type capturedRun struct {
	path string
	args []string
	env  []string
	ctx  context.Context
	mu   sync.Mutex
	call int
}

func (run *capturedRun) Run(ctx context.Context, path string, args []string, env []string) ([]byte, []byte, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	run.path, run.args, run.env, run.ctx = path, append([]string(nil), args...), append([]string(nil), env...), ctx
	run.call++
	return []byte("sensitive stdout"), []byte("sensitive stderr"), nil
}

func TestExecutorExactCommandsAndTruthfulResults(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		kind  CommandType
		args  []string
		state OperationResultState
	}{
		{name: "reboot", kind: CommandReboot, args: []string{"reboot"}, state: ResultScheduled},
		{name: "poweroff", kind: CommandPoweroff, args: []string{"poweroff"}, state: ResultScheduled},
		{name: "update", kind: CommandSystemUpdate, args: []string{"start", "--wait", "novakiosk-system-update@rpm-ostree.service"}, state: ResultStaged},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			run := &capturedRun{}
			executor := NewExecutor(OperationConfig{Runner: run, FS: operationFS(), SystemctlPath: DefaultSystemctlPath, Clock: func() time.Time { return time.Date(2026, 8, 24, 12, 0, 0, 0, time.FixedZone("test", 3600)) }})
			result := executor.Execute(context.Background(), testCase.kind)
			if result.Result != testCase.state || result.ErrorCategory != nil {
				t.Fatalf("result = %#v", result)
			}
			if !reflect.DeepEqual(run.args, testCase.args) {
				t.Fatalf("argv = %#v, want %#v", run.args, testCase.args)
			}
			if run.path != DefaultSystemctlPath || !reflect.DeepEqual(run.env, []string{"LC_ALL=C", "LANG=C"}) {
				t.Fatalf("path/env = %q %#v", run.path, run.env)
			}
			if run.ctx == nil {
				t.Fatal("runner received nil context")
			}
			if err := result.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			encoded, err := json.Marshal(result)
			if err != nil || strings.Contains(string(encoded), "sensitive") || strings.Contains(string(encoded), "stderr") {
				t.Fatalf("result leaked output: %s (err=%v)", encoded, err)
			}
		})
	}
}

func TestExecutorUpdatePreflightStopsBeforeRunner(t *testing.T) {
	run := &capturedRun{}
	filesystem := operationFS()
	delete(filesystem.files, OstreeBootedPath)
	delete(filesystem.infos, OstreeBootedPath)
	executor := NewExecutor(OperationConfig{Runner: run, FS: filesystem, SystemctlPath: DefaultSystemctlPath})
	result := executor.Execute(context.Background(), CommandSystemUpdate)
	if result.Result != ResultFailed || result.ErrorCategory == nil || *result.ErrorCategory != ErrorPreflightFailed {
		t.Fatalf("result = %#v", result)
	}
	if run.call != 0 {
		t.Fatalf("runner call count = %d", run.call)
	}
}

func TestExecutorRunnerFailureTimeoutAndMaliciousType(t *testing.T) {
	filesystem := operationFS()
	called := 0
	executor := NewExecutor(OperationConfig{FS: filesystem, SystemctlPath: DefaultSystemctlPath, Runner: RunnerFunc(func(context.Context, string, []string, []string) ([]byte, []byte, error) {
		called++
		return nil, nil, errors.New("secret command stderr")
	})})
	failure := executor.Execute(context.Background(), CommandReboot)
	if failure.Result != ResultFailed || failure.ErrorCategory == nil || *failure.ErrorCategory != ErrorCommandFailed {
		t.Fatalf("failure = %#v", failure)
	}
	if called != 1 {
		t.Fatalf("runner calls = %d", called)
	}

	timeoutExecutor := NewExecutor(OperationConfig{FS: filesystem, SystemctlPath: DefaultSystemctlPath, CommandTimeout: 10 * time.Millisecond, Runner: RunnerFunc(func(ctx context.Context, _ string, _ []string, _ []string) ([]byte, []byte, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})})
	timeout := timeoutExecutor.Execute(context.Background(), CommandPoweroff)
	if timeout.ErrorCategory == nil || *timeout.ErrorCategory != ErrorTimeout {
		t.Fatalf("timeout = %#v", timeout)
	}

	malicious := executor.Execute(context.Background(), CommandType("systemctl reboot; touch /tmp/pwned"))
	if malicious.ErrorCategory == nil || *malicious.ErrorCategory != ErrorInvalidCommand {
		t.Fatalf("malicious = %#v", malicious)
	}
	if called != 1 {
		t.Fatalf("malicious operation reached runner: %d", called)
	}
}

func TestExecutablePresenceRequiresRegularExecutableFile(t *testing.T) {
	for _, test := range []struct {
		mode fs.FileMode
		want bool
	}{{0, false}, {0644, false}, {0755, true}, {fs.ModeDir | 0755, false}, {fs.ModeSymlink | 0777, false}} {
		filesystem := newFakeFS()
		filesystem.addFile(DefaultSystemctlPath, "", test.mode)
		if got := executablePresent(filesystem, DefaultSystemctlPath); got != test.want {
			t.Fatalf("mode %v: got %v want %v", test.mode, got, test.want)
		}
	}
}

func TestProductionRunnerEnforcesOutputLimits(t *testing.T) {
	for _, script := range []string{"printf 123456789", "printf 123456789 >&2"} {
		_, _, err := (productionRunner{maxOutputBytes: 4}).Run(t.Context(), "/bin/sh", []string{"-c", script}, nil)
		if !errors.Is(err, errOperationOutputLimit) {
			t.Fatalf("output bound bypassed: %v", err)
		}
	}
}
