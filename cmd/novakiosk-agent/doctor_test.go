package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDoctorExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeDoctorFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func completeDoctorConfig(t *testing.T, direct bool) doctorConfig {
	t.Helper()
	root := t.TempDir()
	paths := doctorPaths{
		ChromiumCandidates: []string{filepath.Join(root, "chromium")},
		WOLUnit:            filepath.Join(root, "novakiosk-wol.service"),
		WOLHelper:          filepath.Join(root, "enable-wol.sh"),
		UpdateUnit:         filepath.Join(root, "novakiosk-system-update@.service"),
		UpdateTool:         filepath.Join(root, "novakiosk-system-update"),
		OstreeBooted:       filepath.Join(root, "ostree-booted"),
		PowerRule:          filepath.Join(root, "90-novakiosk.rules"),
		Systemctl:          []string{filepath.Join(root, "systemctl")},
		RPMOstree:          []string{filepath.Join(root, "rpm-ostree")},
	}
	if direct {
		writeDoctorExecutable(t, paths.ChromiumCandidates[0])
	}
	writeDoctorFile(t, paths.WOLUnit)
	writeDoctorExecutable(t, paths.WOLHelper)
	writeDoctorFile(t, paths.UpdateUnit)
	writeDoctorExecutable(t, paths.UpdateTool)
	writeDoctorFile(t, paths.OstreeBooted)
	writeDoctorFile(t, paths.PowerRule)
	writeDoctorExecutable(t, paths.Systemctl[0])
	writeDoctorExecutable(t, paths.RPMOstree[0])
	return doctorConfig{Paths: paths, FS: hostDoctorFileSystem{}, LookPath: func(string) (string, error) { return "", os.ErrNotExist }}
}

func TestInspectDoctorDirectChromiumIsReadyWithoutExecutingCommands(t *testing.T) {
	config := completeDoctorConfig(t, true)
	report := inspectDoctor(config)
	if !report.Ready {
		t.Fatalf("report is not ready: %+v", report)
	}
	if report.Findings[0].Status != "available" {
		t.Fatalf("direct finding = %+v", report.Findings[0])
	}
	var output bytes.Buffer
	report.writeTo(&output)
	if !strings.Contains(output.String(), "no commands executed") {
		t.Fatalf("doctor output = %q", output.String())
	}
}

func TestInspectDoctorReportsMissingChromiumAsNotReady(t *testing.T) {
	config := completeDoctorConfig(t, false)
	report := inspectDoctor(config)
	if report.Ready {
		t.Fatal("missing Chromium report unexpectedly marked ready")
	}
	if report.Findings[0].Status != "missing" {
		t.Fatalf("direct finding = %+v", report.Findings[0])
	}
	var output bytes.Buffer
	report.writeTo(&output)
	if !strings.Contains(output.String(), "hardware preflight failed") {
		t.Fatalf("doctor output = %q", output.String())
	}
}

func TestInspectDoctorUsesInjectedLookupForNamedChromium(t *testing.T) {
	config := completeDoctorConfig(t, false)
	config.ChromiumPath = "chromium-test"
	called := false
	config.LookPath = func(name string) (string, error) {
		called = true
		if name != "chromium-test" {
			t.Fatalf("looked up %q", name)
		}
		return config.Paths.ChromiumCandidates[0], nil
	}
	report := inspectDoctor(config)
	if !called || report.Findings[0].Status != "available" {
		t.Fatalf("lookup called = %t, finding = %+v", called, report.Findings[0])
	}
}

func TestInspectDoctorRequiresExecutableOSHelpers(t *testing.T) {
	config := completeDoctorConfig(t, true)
	if err := os.Chmod(config.Paths.WOLHelper, 0o644); err != nil {
		t.Fatal(err)
	}
	report := inspectDoctor(config)
	if report.Ready {
		t.Fatal("non-executable WoL helper unexpectedly passed preflight")
	}
	var finding *doctorFinding
	for index := range report.Findings {
		if report.Findings[index].Name == "WoL prerequisite" {
			finding = &report.Findings[index]
			break
		}
	}
	if finding == nil || finding.Status != "missing" {
		t.Fatalf("WoL finding = %+v", finding)
	}
}

func TestInspectDoctorRequiresOstreeBootedMarkerForUpdate(t *testing.T) {
	config := completeDoctorConfig(t, true)
	if err := os.Remove(config.Paths.OstreeBooted); err != nil {
		t.Fatal(err)
	}
	report := inspectDoctor(config)
	if report.Ready {
		t.Fatal("missing /run/ostree-booted marker unexpectedly passed preflight")
	}
	var finding *doctorFinding
	for index := range report.Findings {
		if report.Findings[index].Name == "OS update prerequisite" {
			finding = &report.Findings[index]
			break
		}
	}
	if finding == nil || finding.Status != "missing" || !strings.Contains(finding.Detail, "/run/ostree-booted") {
		t.Fatalf("OS update finding = %+v", finding)
	}
}

func TestInspectDoctorSwayModeRequiresDirectChromium(t *testing.T) {
	config := completeDoctorConfig(t, true)
	root := filepath.Dir(config.Paths.ChromiumCandidates[0])
	config.RuntimeMode = "sway"
	config.Paths.Sway = filepath.Join(root, "sway")
	config.Paths.SwayMsg = filepath.Join(root, "swaymsg")
	config.Paths.SwayConfig = filepath.Join(root, "sway-config")
	writeDoctorExecutable(t, config.Paths.Sway)
	writeDoctorExecutable(t, config.Paths.SwayMsg)
	report := inspectDoctor(config)
	if !report.Ready {
		t.Fatalf("Sway report is not ready: %+v", report)
	}
	if report.Findings[0].Status != "available" {
		t.Fatalf("direct Chromium finding = %+v", report.Findings[0])
	}
	var configFinding *doctorFinding
	for index := range report.Findings {
		if report.Findings[index].Name == "Sway user config" {
			configFinding = &report.Findings[index]
			break
		}
	}
	if configFinding == nil || configFinding.Status != "will-create" || !configFinding.Ready {
		t.Fatalf("missing Sway config finding = %+v", configFinding)
	}
	var modeFinding *doctorFinding
	for index := range report.Findings {
		if report.Findings[index].Name == "Evaluated runtime mode" {
			modeFinding = &report.Findings[index]
			break
		}
	}
	if modeFinding == nil || modeFinding.Status != "sway" || !strings.Contains(modeFinding.Detail, "direct Chromium") {
		t.Fatalf("runtime mode finding = %+v", modeFinding)
	}
}

func TestInspectDoctorPrinterPrerequisiteIsOptionalAndTruthful(t *testing.T) {
	config := completeDoctorConfig(t, true)
	config.Paths.LPStat = filepath.Join(t.TempDir(), "lpstat")
	// The rest of the kiosk preflight can be complete even when CUPS is absent.
	report := inspectDoctor(config)
	var finding *doctorFinding
	for index := range report.Findings {
		if report.Findings[index].Name == "Printer hardware-test prerequisite" {
			finding = &report.Findings[index]
			break
		}
	}
	if finding == nil || finding.Status != "missing" || !finding.Ready || !strings.Contains(finding.Detail, "physical") && !strings.Contains(finding.Detail, "printer evidence") {
		t.Fatalf("printer finding = %+v", finding)
	}
}
