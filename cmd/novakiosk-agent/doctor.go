package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// doctorFileSystem inspects prerequisites without opening or executing them.
type doctorFileSystem interface {
	Stat(string) (os.FileInfo, error)
}

type hostDoctorFileSystem struct{}

func (hostDoctorFileSystem) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

type doctorPaths struct {
	ChromiumCandidates []string
	Sway               string
	SwayMsg            string
	WayVNC             string
	SwayConfig         string
	LPStat             string

	WOLUnit      string
	WOLHelper    string
	UpdateUnit   string
	UpdateTool   string
	OstreeBooted string
	PowerRule    string
	Systemctl    []string
	RPMOstree    []string
}

func defaultDoctorPaths() doctorPaths {
	swayConfig := ""
	if configDir, err := os.UserConfigDir(); err == nil && configDir != "" {
		swayConfig = filepath.Join(configDir, "sway", "config")
	}
	return doctorPaths{
		ChromiumCandidates: []string{"/usr/bin/chromium", "/usr/bin/chromium-browser"},
		Sway:               "/usr/bin/sway",
		SwayMsg:            "/usr/bin/swaymsg",
		WayVNC:             "/usr/bin/wayvnc",
		SwayConfig:         swayConfig,
		LPStat:             "/usr/bin/lpstat",
		WOLUnit:            "/usr/lib/systemd/system/novakiosk-wol.service",
		WOLHelper:          "/usr/libexec/novakiosk/enable-wol.sh",
		UpdateUnit:         "/usr/lib/systemd/system/novakiosk-system-update@.service",
		UpdateTool:         "/usr/libexec/novakiosk-system-update",
		OstreeBooted:       "/run/ostree-booted",
		PowerRule:          "/usr/share/polkit-1/rules.d/90-novakiosk.rules",
		Systemctl:          []string{"/usr/bin/systemctl", "/bin/systemctl"},
		RPMOstree:          []string{"/usr/bin/rpm-ostree", "/bin/rpm-ostree"},
	}
}

type doctorConfig struct {
	ChromiumPath string
	RuntimeMode  string
	Paths        doctorPaths
	FS           doctorFileSystem
	LookPath     func(string) (string, error)
}

func defaultDoctorConfig(chromiumPath string) doctorConfig {
	return doctorConfig{
		ChromiumPath: chromiumPath,
		RuntimeMode:  "browser",
		Paths:        defaultDoctorPaths(),
		FS:           hostDoctorFileSystem{},
		LookPath:     exec.LookPath,
	}
}

type doctorFinding struct {
	Name   string
	Status string
	Detail string
	Ready  bool
}

type doctorReport struct {
	Findings []doctorFinding
	Ready    bool
}

func (report doctorReport) writeTo(writer io.Writer) {
	for _, finding := range report.Findings {
		fmt.Fprintf(writer, "%s: %s (%s)\n", finding.Name, finding.Status, finding.Detail)
	}
	if report.Ready {
		fmt.Fprintln(writer, "doctor: hardware preflight passed (no commands executed)")
	} else {
		fmt.Fprintln(writer, "doctor: hardware preflight failed (no commands executed)")
	}
}

func doctor(args []string) {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	chromium := flags.String("chromium", "", "direct Chromium executable path to inspect")
	runtimeMode := flags.String("runtime-mode", "browser", "runtime mode: browser or sway")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	config := defaultDoctorConfig(*chromium)
	config.RuntimeMode = *runtimeMode
	report := inspectDoctor(config)
	report.writeTo(os.Stdout)
	if !report.Ready {
		os.Exit(1)
	}
}

func inspectDoctor(config doctorConfig) doctorReport {
	if config.FS == nil {
		config.FS = hostDoctorFileSystem{}
	}
	if config.LookPath == nil {
		config.LookPath = exec.LookPath
	}
	if len(config.Paths.ChromiumCandidates) == 0 {
		config.Paths = defaultDoctorPaths()
	}
	mode := strings.ToLower(strings.TrimSpace(config.RuntimeMode))
	if mode == "" {
		mode = "browser"
	}
	if mode != "browser" && mode != "sway" {
		return doctorReport{Findings: []doctorFinding{{Name: "runtime mode", Status: "invalid", Detail: "must be browser or sway", Ready: false}}, Ready: false}
	}
	directPath, directReady := doctorChromiumPath(config)

	findings := []doctorFinding{
		{Name: "direct Chromium", Status: "missing", Detail: "no executable candidate found; --remote-debugging-pipe was not executed", Ready: false},
	}
	if directReady {
		findings[0] = doctorFinding{
			Name: "direct Chromium", Status: "available",
			Detail: fmt.Sprintf("%s; --remote-debugging-pipe was not executed", directPath), Ready: true,
		}
	}
	if mode == "sway" {
		findings = append(findings,
			doctorRequirement(config, "Sway runtime prerequisite", []doctorPathRequirement{
				{paths: []string{config.Paths.Sway}, executable: true},
				{paths: []string{config.Paths.SwayMsg}, executable: true},
			}, "requires executable sway and swaymsg; the runtime applier creates the user config"),
		)
		configStatus := "will-create"
		configDetail := "the runtime applier creates the user Sway config before reload"
		if doctorPathPresent(config.FS, config.Paths.SwayConfig, false) {
			configStatus = "present"
			configDetail = "the user Sway config is present; the runtime applier manages its contents"
		}
		findings = append(findings, doctorFinding{
			Name: "Sway user config", Status: configStatus, Detail: configDetail, Ready: true,
		})
		wayvnc := doctorFinding{Name: "WayVNC remote-desktop prerequisite", Status: "missing", Detail: config.Paths.WayVNC + " is not present; remote desktop remains unavailable", Ready: true}
		if doctorPathPresent(config.FS, config.Paths.WayVNC, true) {
			wayvnc = doctorFinding{Name: "WayVNC remote-desktop prerequisite", Status: "available", Detail: config.Paths.WayVNC + " is present; it starts only on explicit request", Ready: true}
		}
		findings = append(findings, wayvnc)
	}

	findings = append(findings,
		doctorRequirement(config, "WoL prerequisite", []doctorPathRequirement{
			{paths: []string{config.Paths.WOLUnit}},
			{paths: []string{config.Paths.WOLHelper}, executable: true},
		}, "requires unit and executable enable helper"),
		doctorRequirement(config, "OS update prerequisite", []doctorPathRequirement{
			{paths: []string{config.Paths.UpdateUnit}},
			{paths: []string{config.Paths.UpdateTool}, executable: true},
			{paths: config.Paths.RPMOstree, executable: true},
			{paths: []string{config.Paths.OstreeBooted}},
		}, "requires unit, executable helper, rpm-ostree, and /run/ostree-booted"),
		doctorRequirement(config, "power prerequisite", []doctorPathRequirement{
			{paths: []string{config.Paths.PowerRule}},
			{paths: config.Paths.Systemctl, executable: true},
		}, "requires polkit rule and systemctl"),
		// Printer evidence is read-only and optional for unrelated agent
		// readiness. Keep this finding explicit so hardware testing can see a
		// missing fixed CUPS client without making kiosk runtime fail closed.
		doctorFinding{
			Name: "Printer hardware-test prerequisite", Status: "missing",
			Detail: "/usr/bin/lpstat is not present; printer evidence will be unavailable",
			Ready:  true,
		},
	)
	if doctorPathPresent(config.FS, config.Paths.LPStat, true) {
		findings[len(findings)-1] = doctorFinding{
			Name: "Printer hardware-test prerequisite", Status: "available",
			Detail: "/usr/bin/lpstat is present; physical readiness remains unknown",
			Ready:  true,
		}
	}
	runtimeDetail := fmt.Sprintf("runtime mode %s evaluated", mode)
	if mode == "sway" {
		runtimeDetail += "; packaged direct Chromium is required for the agent-managed browser"
	} else {
		runtimeDetail += "; direct Chromium is required for browser-mode CDP"
	}
	findings = append(findings, doctorFinding{
		Name: "Evaluated runtime mode", Status: mode,
		Detail: runtimeDetail,
		Ready:  true,
	})

	ready := true
	for _, finding := range findings {
		if !finding.Ready {
			ready = false
		}
	}
	return doctorReport{Findings: findings, Ready: ready}
}

// doctorPathRequirement describes one required path, or a set of alternatives
// where any one path is sufficient.
type doctorPathRequirement struct {
	paths      []string
	executable bool
}

func doctorRequirement(config doctorConfig, name string, requirements []doctorPathRequirement, detail string) doctorFinding {
	for _, requirement := range requirements {
		found := false
		for _, path := range requirement.paths {
			if doctorPathPresent(config.FS, path, requirement.executable) {
				found = true
				break
			}
		}
		if !found {
			return doctorFinding{Name: name, Status: "missing", Detail: detail, Ready: false}
		}
	}
	return doctorFinding{Name: name, Status: "present", Detail: detail, Ready: true}
}

func doctorChromiumPath(config doctorConfig) (string, bool) {
	path := strings.TrimSpace(config.ChromiumPath)
	if path != "" {
		if filepath.Separator != '/' && strings.Contains(path, "/") {
			path = filepath.FromSlash(path)
		}
		if strings.ContainsRune(path, os.PathSeparator) {
			return path, doctorExecutable(config.FS, path)
		}
		resolved, err := config.LookPath(path)
		return resolved, err == nil && resolved != ""
	}
	for _, candidate := range config.Paths.ChromiumCandidates {
		if doctorExecutable(config.FS, candidate) {
			return candidate, true
		}
	}
	for _, candidate := range []string{"chromium", "chromium-browser"} {
		resolved, err := config.LookPath(candidate)
		if err == nil && resolved != "" {
			return resolved, true
		}
	}
	return "", false
}

func doctorExecutable(fileSystem doctorFileSystem, path string) bool {
	return doctorPathPresent(fileSystem, path, true)
}

func doctorPathPresent(fileSystem doctorFileSystem, path string, executable bool) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := fileSystem.Stat(path)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return false
	}
	if executable && info.Mode()&0o111 == 0 {
		return false
	}
	return true
}
