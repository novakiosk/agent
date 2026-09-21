package cupsjob

import (
	"context"
	"errors"
	"github.com/novakiosk/agent/printer"
	"slices"
	"strings"
	"testing"
)

func TestAddUSBQueueBoundToAttachedDevice(t *testing.T) {
	uri := "usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=TEST123"
	queue := printer.USBQueueName(printer.USBDeviceID("TEST123"))
	for _, scenario := range []string{"empty-cups", "another-queue", "disconnected", "foreign-device", "collision", "duplicate", "cups-unavailable", "add-failed", "postcheck-failed", "bridge"} {
		t.Run(scenario, func(t *testing.T) {
			profile := "kiosk"
			if scenario == "bridge" {
				profile = "print-bridge"
			}
			request := Request{Version: 1, Type: QueueRequestType, Profile: profile, Action: ActionAddUSB, CommandHash: strings.Repeat("a", 64), QueueName: queue}
			mutations := 0
			runner := printer.RunnerFunc(func(_ context.Context, path string, args, env []string) ([]byte, []byte, error) {
				switch path {
				case "/usr/sbin/lpinfo":
					if !slices.Equal(args, []string{"--include-schemes", "usb", "-v"}) {
						t.Fatal(args)
					}
					if scenario == "disconnected" {
						return nil, nil, nil
					}
					if scenario == "foreign-device" {
						return []byte("direct socket://192.168.1.1:9100\n"), nil, nil
					}
					return []byte("direct " + uri + "\n"), nil, nil
				case "/usr/bin/lpstat":
					if args[0] == "-e" {
						if scenario == "cups-unavailable" {
							return nil, nil, errors.New("offline")
						}
						if scenario == "collision" {
							return []byte(queue + "\n"), nil, nil
						}
						if scenario == "duplicate" || scenario == "another-queue" {
							return []byte("Existing\n"), nil, nil
						}
						return nil, nil, nil
					}
					if len(args) == 1 {
						existingURI := uri
						if scenario == "another-queue" {
							existingURI = "socket://192.168.1.1:9100"
						}
						return []byte("device for Existing: " + existingURI + "\n"), nil, nil
					}
					if scenario == "postcheck-failed" {
						return nil, nil, errors.New("missing")
					}
					return []byte("device for " + queue + ": " + uri + "\n"), nil, nil
				case "/usr/sbin/lpadmin":
					mutations++
					if !slices.Equal(args, []string{"-p", queue, "-E", "-v", uri, "-m", "drv:///sample.drv/zebra.ppd", "-D", "ZTC ZD421-203dpi ZPL", "-o", "printer-is-shared=false"}) {
						t.Fatal(args)
					}
					if scenario == "add-failed" {
						return nil, nil, errors.New("driver missing")
					}
					return nil, nil, nil
				default:
					t.Fatalf("unexpected %s", path)
					return nil, nil, nil
				}
			})
			result := runQueueAction(context.Background(), HelperConfig{Profile: profile}, runner, request)
			want := ResultFailed
			if scenario == "empty-cups" || scenario == "another-queue" {
				want = ResultApplied
			}
			if result.Result != want {
				t.Fatalf("%+v", result)
			}
			mayMutate := want == ResultApplied || scenario == "add-failed" || scenario == "postcheck-failed"
			if !mayMutate && mutations != 0 {
				t.Fatal("unexpected mutation")
			}
			if profile == "kiosk" && (request.Validate(profile) != nil || result.Validate(profile) != nil) {
				t.Fatal("protocol rejects add")
			}
			if profile == "print-bridge" && request.Validate(profile) == nil {
				t.Fatal("bridge can add USB")
			}
		})
	}
}
