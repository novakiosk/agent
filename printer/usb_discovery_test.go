package printer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUSBDiscoveryWithoutConfiguredQueue(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "1-1")
	if err := os.Mkdir(device, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"idVendor": "0a5f", "serial": "TEST123", "product": "ZTC ZD421-203dpi ZPL"} {
		if err := os.WriteFile(filepath.Join(device, name), []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configured := ""
	p := NewProbe(Config{USBSysfsRoot: root, Runner: RunnerFunc(func(_ context.Context, path string, args, env []string) ([]byte, []byte, error) {
		if path != "/usr/bin/lpstat" {
			t.Fatalf("unexpected path: %s", path)
		}
		if args[0] == "-e" {
			return []byte(configured), nil, nil
		}
		if args[0] == "-v" {
			return []byte("device for Existing: usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=TEST123\n"), nil, nil
		}
		return nil, nil, errors.New("unexpected call")
	})})
	report := p.discoverUSB(context.Background())
	if !validUSBDiscovery(*report) || len(report.Devices) != 1 || report.Devices[0].ConfiguredQueue != nil || report.Devices[0].ID != USBDeviceID("TEST123") {
		t.Fatalf("unexpected discovery: %+v", report)
	}
	configured = "Existing\n"
	report = p.discoverUSB(context.Background())
	if len(report.Devices) != 1 || report.Devices[0].ConfiguredQueue == nil || *report.Devices[0].ConfiguredQueue != "Existing" {
		t.Fatalf("configured queue missing: %+v", report)
	}
	configured = "" // Removing a queue must not hide the attached device.
	if report = p.discoverUSB(context.Background()); len(report.Devices) != 1 || report.Devices[0].ConfiguredQueue != nil {
		t.Fatal("device cannot be re-added")
	}
}
func TestZebraUSBURIRejectsForeignBackendsAndOptions(t *testing.T) {
	base := "usb://Zebra%20Technologies/ZTC%20ZD421-203dpi%20ZPL?serial=TEST123"
	if _, _, ok := ZebraUSBURI(base); !ok {
		t.Fatal("valid Zebra rejected")
	}
	for _, uri := range []string{strings.Replace(base, "usb://", "socket://", 1), base + "&x=1", base + "&serial=OTHER", strings.Replace(base, "%20ZPL", "%20EPL", 1), strings.Replace(base, "TEST123", "../file", 1)} {
		if _, _, ok := ZebraUSBURI(uri); ok {
			t.Fatalf("accepted %q", uri)
		}
	}
}
func TestUSBDiscoveryCanonicalFixture(t *testing.T) {
	report := Report{Version: 1, Type: Type, Source: Source, ObservedAt: "2026-09-21T10:00:00Z", Scheduler: SchedulerRunning, Transport: TransportReachable, Queues: []QueueReport{}, USBDiscovery: &USBDiscovery{Devices: []USBDevice{{ID: USBDeviceID("TEST123"), Name: "ZTC ZD421-203dpi ZPL"}}}}
	hash, err := CanonicalPayloadHash(report)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "afec4383b49331d7df4b4a9bf3e4b493532cc5c345b2b22eaa613661ed4b83ee"
	if hash != expected {
		t.Fatalf("USB fixture hash: %s", hash)
	}
}
