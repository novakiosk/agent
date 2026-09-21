package cupsreconcile

import (
	"context"
	"errors"
	"github.com/novakiosk/agent/printer"
	"strings"
	"testing"
)

func defaultDesired(t *testing.T, mode string) Desired {
	t.Helper()
	name := "NOVA_test"
	queue := Queue{PrinterID: "printer-test", LocalName: name, Mode: mode, Options: []Option{}}
	if mode == ModeRemote {
		queue.RemoteURI = "ipp://192.168.1.2:631/printers/Zebra"
	}
	desired := Desired{Version: 1, Type: DesiredType, SessionID: "session", DeviceID: "device", Queues: []Queue{queue}, DefaultQueue: &name}
	var err error
	desired.DesiredHash, err = desired.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	return desired
}
func TestMaintainDefaultSurvivesHealthAndReassertsDrift(t *testing.T) {
	for _, mode := range []string{ModeExisting, ModeRemote} {
		t.Run(mode, func(t *testing.T) {
			desired := defaultDesired(t, mode)
			current := "PDF"
			sets := 0
			fail := false
			badPostcheck := false
			runner := printer.RunnerFunc(func(_ context.Context, path string, args, env []string) ([]byte, []byte, error) {
				if len(env) != 1 || !strings.HasPrefix(env[0], "HOME=") {
					t.Fatal("missing user home")
				}
				if fail {
					return nil, nil, errors.New("CUPS unavailable")
				}
				if path == "/usr/bin/lpstat" && args[0] == "-v" {
					uri := "usb://Zebra/OfflineDevice"
					if mode == ModeRemote {
						uri = desired.Queues[0].RemoteURI
					}
					return []byte("device for NOVA_test: " + uri + "\n"), nil, nil
				}
				if path == "/usr/bin/lpstat" && args[0] == "-d" {
					return []byte("system default destination: " + current + "\n"), nil, nil
				}
				if path == "/usr/bin/lpoptions" && len(args) == 2 && args[0] == "-d" && args[1] == "NOVA_test" {
					sets++
					if !badPostcheck {
						current = args[1]
					}
					return nil, nil, nil
				}
				t.Fatalf("unexpected command: %s %v", path, args)
				return nil, nil, nil
			})
			reconciler := Reconciler{Profile: "kiosk", DefaultRunner: runner}
			if err := reconciler.MaintainDefault(context.Background(), desired); err != nil || sets != 1 {
				t.Fatalf("initial: %v %d", err, sets)
			}
			if err := reconciler.MaintainDefault(context.Background(), desired); err != nil || sets != 1 {
				t.Fatalf("rewrote unchanged default: %v", err)
			}
			current = "Other"
			if err := reconciler.MaintainDefault(context.Background(), desired); err != nil || sets != 2 {
				t.Fatal("drift not corrected")
			}
			fail = true
			if err := reconciler.MaintainDefault(context.Background(), desired); err == nil || current != "NOVA_test" || sets != 2 {
				t.Fatal("CUPS outage changed default or claimed success")
			}
			fail = false
			current = "Other"
			badPostcheck = true
			if reconciler.MaintainDefault(context.Background(), desired) == nil {
				t.Fatal("failed postcheck accepted")
			}
			reconciler.Profile = "print-bridge"
			if reconciler.MaintainDefault(context.Background(), desired) == nil {
				t.Fatal("bridge changed default")
			}
		})
	}
}
func TestDefaultSelectionBoundToDesiredHashAndMembership(t *testing.T) {
	desired := defaultDesired(t, ModeExisting)
	if desired.Validate() != nil {
		t.Fatal("valid default rejected")
	}
	original := desired.DesiredHash
	other := "another-queue"
	desired.DefaultQueue = &other
	desired.DesiredHash, _ = desired.PayloadHash()
	if desired.Validate() == nil {
		t.Fatal("foreign default accepted")
	}
	desired.DefaultQueue = nil
	desired.DesiredHash, _ = desired.PayloadHash()
	if desired.Validate() != nil || desired.DesiredHash == original {
		t.Fatal("default not hashed independently")
	}
	desired = defaultDesired(t, ModeExisting)
	if desired.DesiredHash != "9efd8733bd0a711ad819431db2f451de103b6abd2e747cf9e329eefdce9e4c3c" {
		t.Fatalf("fixture hash %s", desired.DesiredHash)
	}
}

func TestMaintainDefaultRejectsReboundDestination(t *testing.T) {
	for _, mode := range []string{ModeRemote, ModeExisting} {
		t.Run(mode, func(t *testing.T) {
			desired := defaultDesired(t, mode)
			writes := 0
			current := "Other"
			runner := printer.RunnerFunc(func(_ context.Context, path string, args, env []string) ([]byte, []byte, error) {
				switch path {
				case "/usr/bin/lpstat":
					if args[0] == "-v" {
						return []byte("device for NOVA_test: ipp://192.168.1.99:631/printers/Other\n"), nil, nil
					}
					return []byte("system default destination: " + current + "\n"), nil, nil
				case "/usr/bin/lpoptions":
					writes++
					current = "NOVA_test"
					return nil, nil, nil
				default:
					t.Errorf("unexpected command: %s %v", path, args)
					return nil, nil, errors.New("unexpected command")
				}
			})
			err := (Reconciler{Profile: "kiosk", DefaultRunner: runner}).MaintainDefault(context.Background(), desired)
			if err == nil || writes != 0 {
				t.Fatalf("rebound destination: error=%v lpoptions writes=%d", err, writes)
			}
		})
	}
}
