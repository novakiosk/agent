package cupsreconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type claimCleanupRunner struct {
	directRunner
	failDelete      bool
	failEnumeration bool
}

func (r *claimCleanupRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	if path == "/usr/bin/lpstat" && len(args) == 1 && args[0] == "-e" && r.failEnumeration {
		return nil, errors.New("enumeration failed")
	}
	if path == "/usr/sbin/lpadmin" && len(args) == 2 && args[0] == "-x" && r.failDelete {
		return nil, errors.New("cleanup failed")
	}
	return r.directRunner.Run(ctx, path, args)
}

func TestDirectCleanupRetainsInterruptedClaimsUntilSuccess(t *testing.T) {
	for _, kind := range []string{"created", "absent", "failed-retry", "enumeration-retry"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "print-bridge.json")
			name := "NOVA_ORPHAN"
			previous := ownedManifest{Version: Version2, Queues: []string{}, Claims: []string{name}, Settings: map[string][]string{}}
			if err := os.WriteFile(manifestPath, mustMarshal(previous), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &claimCleanupRunner{existing: map[string]bool{name: kind != "absent", "Office@Lab": true}, failDelete: kind == "failed-retry", failEnumeration: kind == "enumeration-retry"}
			config := HelperConfig{ManifestDir: dir, Profile: "print-bridge", CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}
			request := HelperRequestV2{Queues: []Queue{}}
			err := applyDirectQueues(context.Background(), runner, config, request)
			if kind == "failed-retry" || kind == "enumeration-retry" {
				if err == nil || !runner.existing[name] || !slices.Contains(loadManifest(manifestPath).Claims, name) {
					t.Fatalf("failed cleanup lost ownership: %v %+v", err, loadManifest(manifestPath))
				}
				runner.failDelete = false
				runner.failEnumeration = false
				err = applyDirectQueues(context.Background(), runner, config, request)
			}
			if err != nil {
				t.Fatal(err)
			}
			after := loadManifest(manifestPath)
			if runner.existing[name] || len(after.Queues) != 0 || len(after.Claims) != 0 || !runner.existing["Office@Lab"] {
				t.Fatalf("cleanup incomplete or unmanaged mutated: %+v %+v", after, runner.existing)
			}
			if kind == "absent" {
				for _, call := range runner.calls {
					if len(call) > 1 && call[1] == "-x" {
						t.Fatal("attempted deleting never-created queue")
					}
				}
			}
		})
	}
}

func TestDirectOversizedStagingPreservesPreviousManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "print-bridge.json")
	previous := ownedManifest{Version: Version2, Queues: []string{}, Settings: map[string][]string{}}
	// Fill a loadable interrupted-claim journal close to its read bound.
	for i := 0; ; i++ {
		name := fmt.Sprintf("NOVA_%04d_%s", i, strings.Repeat("X", 110))
		previous.Claims = append(previous.Claims, name)
		if len(mustMarshal(previous)) > MaxMessageBytes-64 {
			previous.Claims = previous.Claims[:len(previous.Claims)-1]
			break
		}
	}
	data := mustMarshal(previous)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	runner := &directRunner{existing: map[string]bool{}}
	config := HelperConfig{ManifestDir: dir, Profile: "print-bridge", CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}
	queues := []Queue{{Mode: ModeDirect, LocalName: "NOVA_NEW_A_" + strings.Repeat("X", 110)}, {Mode: ModeDirect, LocalName: "NOVA_NEW_B_" + strings.Repeat("X", 110)}}
	if err := applyDirectQueues(context.Background(), runner, config, HelperRequestV2{Queues: queues}); err == nil || !strings.Contains(err.Error(), "staged manifest too large") {
		t.Fatalf("oversized staging accepted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("oversized staging replaced recoverable journal")
	}
	for _, call := range runner.calls {
		if call[0] == "/usr/sbin/lpadmin" {
			t.Fatalf("queue mutated before staging: %v", call)
		}
	}
}

// A transient per-name lookup error must never be mistaken for absence and
// persisted as ownership of an existing unmanaged destination.
type transientCollisionRunner struct {
	directRunner
	failEnumeration bool
	failLookup      bool
}

func (r *transientCollisionRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	if path == "/usr/bin/lpstat" && len(args) == 1 && args[0] == "-e" && r.failEnumeration {
		r.failEnumeration = false
		return nil, context.DeadlineExceeded
	}
	if path == "/usr/bin/lpstat" && len(args) == 2 && args[0] == "-p" && r.failLookup {
		r.failLookup = false
		return nil, context.DeadlineExceeded
	}
	return r.directRunner.Run(ctx, path, args)
}

func TestDirectEnumerationFailureCannotClaimUnmanagedQueue(t *testing.T) {
	runner := &transientCollisionRunner{existing: map[string]bool{"NOVA_COLLISION": true}, failEnumeration: true, failLookup: true}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "print-bridge.json")
	config := HelperConfig{ManifestDir: dir, Profile: "print-bridge", CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}
	request := HelperRequestV2{Version: Version2, Queues: []Queue{{Mode: ModeDirect, LocalName: "NOVA_COLLISION", PrivateIP: "192.168.1.50", DisplayName: "Managed", Location: "Test"}}}
	for attempt := range 2 {
		if err := applyDirectQueues(context.Background(), runner, config, request); err == nil {
			t.Fatalf("attempt %d claimed unmanaged queue", attempt)
		}
		if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
			t.Fatalf("attempt %d changed ownership manifest: %v %+v", attempt, err, loadManifest(manifestPath))
		}
	}
	for _, call := range runner.calls {
		if call[0] == "/usr/sbin/lpadmin" {
			t.Fatalf("unmanaged queue mutated: %v", call)
		}
	}
}

func TestDirectQueueOwnershipUsesCUPSCaseInsensitiveNames(t *testing.T) {
	for _, kind := range []string{"unmanaged", "owned", "obsolete"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			name := "NOVA_Collision"
			actual := "nova_collision"
			path := filepath.Join(dir, "print-bridge.json")
			if kind != "unmanaged" {
				if err := os.WriteFile(path, mustMarshal(ownedManifest{Version: Version2, Queues: []string{name}, Settings: map[string][]string{}}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			runner := &caseInsensitiveDirectRunner{existing: map[string]bool{actual: true}}
			request := HelperRequestV2{Queues: []Queue{{Mode: ModeDirect, LocalName: "NOVA_COLLISION", PrivateIP: "192.168.1.50", DisplayName: "Managed", Location: "Test"}}}
			if kind == "obsolete" {
				request.Queues = nil
			}
			config := HelperConfig{ManifestDir: dir, Profile: "print-bridge", CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}
			err := applyDirectQueues(context.Background(), runner, config, request)
			if kind == "unmanaged" {
				if err == nil {
					t.Fatal("case-fold collision claimed")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("collision changed manifest")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			deletes := 0
			for _, call := range runner.calls {
				if call[0] == "/usr/sbin/lpadmin" {
					if kind == "unmanaged" {
						t.Fatalf("unmanaged mutated: %v", call)
					}
					if call[1] == "-x" {
						deletes++
						if call[2] != name {
							t.Fatalf("deletion used unowned enumeration name: %v", call)
						}
					}
				}
			}
			if kind == "owned" && deletes != 0 {
				t.Fatal("managed desired queue deleted due to case difference")
			}
			if kind == "obsolete" && (deletes != 1 || runner.existing[actual]) {
				t.Fatal("obsolete owned queue not deleted")
			}
		})
	}
}

type caseInsensitiveDirectRunner struct{ directRunner }

func (r *caseInsensitiveDirectRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	if path == "/usr/sbin/lpadmin" && len(args) > 1 && args[0] == "-x" {
		for name := range r.existing {
			if strings.EqualFold(name, args[1]) {
				delete(r.existing, name)
			}
		}
	}
	return r.directRunner.Run(ctx, path, args)
}

func TestLegacyClaimsRecoverPartialRemoteCreation(t *testing.T) {
	for _, retry := range []string{"remove", "complete"} {
		t.Run(retry, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kiosk.json")
			runner := &helperRunner{queues: map[string]bool{"usb": true, "Office@Lab": true}}
			config := HelperConfig{ManifestDir: dir, Profile: "kiosk"}
			request := HelperRequest{Version: Version, Queues: []Queue{{PrinterID: "a", Mode: ModeRemote, LocalName: "NOVA_NEW", RemoteURI: "ipps://print.local:631/printers/new"}, {PrinterID: "b", Mode: ModeExisting, LocalName: "usb", Options: []Option{{Name: "PageSize", Value: "unsupported"}}}}}
			if err := applyQueues(context.Background(), runner, config, request); err == nil || !runner.queues["NOVA_NEW"] {
				t.Fatal("partial creation setup failed")
			}
			if !slices.Contains(loadManifest(path).Claims, "NOVA_NEW") {
				t.Error("created proxy ownership was not durable")
			}
			if retry == "remove" {
				request.Queues = nil
			} else {
				request.Queues[1].Options[0].Value = "4x6"
			}
			if err := applyQueues(context.Background(), runner, config, request); err != nil {
				t.Fatal(err)
			}
			manifest := loadManifest(path)
			if len(manifest.Claims) != 0 || runner.queues["NOVA_NEW"] != (retry == "complete") || !runner.queues["usb"] || !runner.queues["Office@Lab"] {
				t.Fatalf("recovery lost ownership or touched existing queues: %+v %+v", manifest, runner.queues)
			}
		})
	}
}

func TestLegacyClaimsRejectUnmanagedCaseCollision(t *testing.T) {
	dir := t.TempDir()
	runner := &legacyCleanupRunner{queues: map[string]bool{"nova_collision": true}}
	request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeRemote, LocalName: "NOVA_COLLISION", RemoteURI: "ipps://print.local:631/printers/collision"}}}
	if err := applyQueues(context.Background(), runner, HelperConfig{ManifestDir: dir, Profile: "kiosk"}, request); err == nil {
		t.Fatal("unmanaged collision was claimed")
	}
	if _, err := os.Stat(filepath.Join(dir, "kiosk.json")); !os.IsNotExist(err) {
		t.Fatal("collision wrote ownership")
	}
	if !runner.queues["nova_collision"] || len(runner.deleted) != 0 {
		t.Fatal("unmanaged collision changed")
	}
}

func TestLegacyClaimsEnumerationAndStagingFailuresPreserveOwnership(t *testing.T) {
	for _, kind := range []string{"enumeration-failed", "enumeration-oversized", "staging-oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kiosk.json")
			previous := ownedManifest{Version: Version, Queues: []string{}, Claims: []string{"NOVA_OLD"}, Settings: map[string][]string{}}
			if kind == "staging-oversized" {
				for i := 0; ; i++ {
					previous.Claims = append(previous.Claims, fmt.Sprintf("NOVA_%04d_%s", i, strings.Repeat("X", 110)))
					if len(mustMarshal(previous)) > MaxMessageBytes-64 {
						previous.Claims = previous.Claims[:len(previous.Claims)-1]
						break
					}
				}
			}
			original := mustMarshal(previous)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			runner := &legacyCleanupRunner{queues: map[string]bool{"nova_old": true}, oversized: kind == "enumeration-oversized"}
			if kind == "enumeration-failed" {
				runner.enumerationError = errors.New("query failed")
			}
			request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeRemote, LocalName: "NOVA_NEW_A_" + strings.Repeat("X", 110), RemoteURI: "ipps://print.local:631/printers/new"}, {Mode: ModeRemote, LocalName: "NOVA_NEW_B_" + strings.Repeat("X", 110), RemoteURI: "ipps://print.local:631/printers/new2"}}}
			if err := applyQueues(context.Background(), runner, HelperConfig{ManifestDir: dir, Profile: "kiosk"}, request); err == nil {
				t.Fatal("unsafe staging succeeded")
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, data) || len(runner.queues) != 1 || !runner.queues["nova_old"] || len(runner.deleted) != 0 {
				t.Fatal("failed preflight changed ownership or queues")
			}
		})
	}
}

func TestLegacyPartialSettingsRemainOwnedUntilCleanup(t *testing.T) {
	for _, retry := range []string{"empty", "changed"} {
		t.Run(retry, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kiosk.json")
			if err := os.WriteFile(path, mustMarshal(ownedManifest{Version: Version, Claims: []string{"NOVA_OLD"}, Settings: map[string][]string{}}), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &helperRunner{queues: map[string]bool{"a": true, "b": true}}
			config := HelperConfig{ManifestDir: dir, Profile: "kiosk"}
			request := HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeRemote, LocalName: "NOVA_NEW", RemoteURI: "ipps://print.local:631/printers/new"}, {Mode: ModeExisting, LocalName: "a", Options: []Option{{Name: "PageSize", Value: "4x6"}}}, {Mode: ModeExisting, LocalName: "b", Options: []Option{{Name: "PageSize", Value: "unsupported"}}}}}
			if err := applyQueues(context.Background(), runner, config, request); err == nil {
				t.Fatal("expected later option failure")
			}
			pending := loadManifest(path)
			if pending.Defaults["a"]["PageSize"] != "4x6" || !slices.Contains(pending.Settings["a"], "PageSize") || len(pending.Settings["b"]) != 0 || !slices.Contains(pending.Claims, "NOVA_NEW") || !slices.Contains(pending.Claims, "NOVA_OLD") {
				t.Errorf("validated ownership or staged claims lost: %+v", pending)
			}
			request.Queues = nil
			if retry == "changed" {
				request.Queues = []Queue{{Mode: ModeExisting, LocalName: "a"}}
			}
			runner.calls = nil
			if err := applyQueues(context.Background(), runner, config, request); err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(runner.calls, func(call []string) bool {
				return slices.Equal(call, []string{"/usr/sbin/lpadmin", "-p", "a", "-o", "PageSize=4x6"})
			}) {
				t.Fatalf("owned option was not removed: %v", runner.calls)
			}
			if !runner.queues["a"] || !runner.queues["b"] || len(loadManifest(path).Claims) != 0 || len(loadManifest(path).Settings["a"]) != 0 {
				t.Fatal("cleanup lost existing queues or failed to collapse ownership")
			}
		})
	}
}

func TestDirectPartialSettingsRemainOwnedUntilChangedDesired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "print-bridge.json")
	previous := ownedManifest{Version: Version2, Queues: []string{"NOVA_A", "NOVA_B"}, Claims: []string{"NOVA_OLD"}, Settings: map[string][]string{}}
	if err := os.WriteFile(path, mustMarshal(previous), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &directRunner{existing: map[string]bool{"NOVA_A": true, "NOVA_B": true}}
	config := HelperConfig{ManifestDir: dir, Profile: "print-bridge", CUPSConfigPath: writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")}
	request := HelperRequestV2{Queues: []Queue{{Mode: ModeDirect, LocalName: "NOVA_A", PrivateIP: "10.0.0.1", Options: []Option{{Name: "Resolution", Value: "300dpi"}}}, {Mode: ModeDirect, LocalName: "NOVA_B", PrivateIP: "10.0.0.2", Options: []Option{{Name: "Resolution", Value: "unsupported"}}}}}
	if err := applyDirectQueues(context.Background(), runner, config, request); err == nil {
		t.Fatal("expected later option failure")
	}
	pending := loadManifest(path)
	if pending.Defaults["NOVA_A"]["Resolution"] != "203dpi" || !slices.Contains(pending.Settings["NOVA_A"], "Resolution") || len(pending.Settings["NOVA_B"]) != 0 || !slices.Contains(pending.Claims, "NOVA_OLD") || !slices.Contains(pending.Claims, "NOVA_A") {
		t.Errorf("partial settings ownership lost: %+v", pending)
	}
	runner.calls = nil
	request.Queues = request.Queues[:1]
	request.Queues[0].Options = nil
	if err := applyDirectQueues(context.Background(), runner, config, request); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(runner.calls, func(call []string) bool {
		return slices.Equal(call, []string{"/usr/sbin/lpadmin", "-p", "NOVA_A", "-o", "Resolution=203dpi"})
	}) {
		t.Fatalf("owned option was not removed: %v", runner.calls)
	}
	if len(loadManifest(path).Claims) != 0 || len(loadManifest(path).Settings["NOVA_A"]) != 0 {
		t.Fatal("successful desired did not collapse ownership")
	}
}

type blockedSettingsRunner struct {
	CommandRunner
	manifestPath string
}

func (runner *blockedSettingsRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	if path == "/usr/bin/lpoptions" {
		if err := os.Rename(runner.manifestPath, runner.manifestPath+".saved"); err != nil {
			return nil, err
		}
		if err := os.Mkdir(runner.manifestPath, 0700); err != nil {
			return nil, err
		}
	}
	return runner.CommandRunner.Run(ctx, path, args)
}

func TestSettingsStagingFailurePreventsMutation(t *testing.T) {
	for _, mode := range []string{"existing", "direct"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			profile, queue, option := "kiosk", "a", "PageSize"
			version := Version
			if mode == "direct" {
				profile, queue, option, version = "print-bridge", "NOVA_A", "Resolution", Version2
			}
			path := filepath.Join(dir, profile+".json")
			previous := ownedManifest{Version: version, Claims: []string{"NOVA_OLD"}, Settings: map[string][]string{}}
			if mode == "direct" {
				previous.Queues = []string{queue}
			}
			if err := os.WriteFile(path, mustMarshal(previous), 0600); err != nil {
				t.Fatal(err)
			}
			config := HelperConfig{ManifestDir: dir, Profile: profile}
			var calls [][]string
			var applyErr error
			if mode == "existing" {
				runner := &helperRunner{queues: map[string]bool{queue: true}}
				applyErr = applyQueues(context.Background(), &blockedSettingsRunner{CommandRunner: runner, manifestPath: path}, config, HelperRequest{Version: Version, Queues: []Queue{{Mode: ModeExisting, LocalName: queue, Options: []Option{{Name: option, Value: "4x6"}}}}})
				calls = runner.calls
			} else {
				runner := &directRunner{existing: map[string]bool{queue: true}}
				config.CUPSConfigPath = writeCUPSConfig(t, "Listen localhost:631\nBrowsing On\n<Location />\n Allow @LOCAL\n</Location>\n")
				applyErr = applyDirectQueues(context.Background(), &blockedSettingsRunner{CommandRunner: runner, manifestPath: path}, config, HelperRequestV2{Queues: []Queue{{Mode: ModeDirect, LocalName: queue, PrivateIP: "10.0.0.1", Options: []Option{{Name: option, Value: "300dpi"}}}}})
				calls = runner.calls
			}
			if applyErr == nil {
				t.Fatal("blocked settings journal unexpectedly succeeded")
			}
			for _, call := range calls {
				if call[0] == "/usr/sbin/lpadmin" {
					t.Fatalf("mutation preceded durable settings ownership: %v", call)
				}
			}
			saved := loadManifest(path + ".saved")
			if !slices.Contains(saved.Claims, "NOVA_OLD") || len(saved.Settings[queue]) != 0 {
				t.Fatalf("failed staging changed retained authority: %+v", saved)
			}
		})
	}
}
