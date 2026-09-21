package enrollment

import (
	"errors"
	"strings"
	"testing"
)

func TestRuntimeDiagnosticReporterDeduplicatesAndReportsRecovery(t *testing.T) {
	artifact := runtimeTestArtifact(false, nil)
	events := make([]RuntimeDiagnostic, 0, 4)
	reporter := newRuntimeDiagnosticReporter(func(event RuntimeDiagnostic) {
		events = append(events, event)
	})
	first := &runtimeCommandError{command: "/usr/bin/sway", diagnostic: `validator\nfailed`, cause: errors.New("exit status 1")}
	reporter.failure(artifact, "runtime-validation", first)
	reporter.failure(artifact, "runtime-validation", first)
	if len(events) != 1 || events[0].Recovered || events[0].Detail != `validator\nfailed` {
		t.Fatalf("initial diagnostic events = %+v", events)
	}

	changedArtifact := artifact
	changedArtifact.ArtifactHash = "different-artifact"
	reporter.failure(changedArtifact, "runtime-validation", first)
	reporter.failure(changedArtifact, "runtime-reload", first)
	if len(events) != 3 {
		t.Fatalf("changed diagnostic events = %+v", events)
	}
	reporter.applied(changedArtifact)
	if len(events) != 4 || !events[3].Recovered || events[3].ArtifactRevision != artifact.ArtifactRevision {
		t.Fatalf("recovery event = %+v", events)
	}
	reporter.applied(changedArtifact)
	if len(events) != 4 {
		t.Fatalf("duplicate recovery event = %+v", events)
	}
	reporter.failure(changedArtifact, "runtime-reload", first)
	if len(events) != 5 || events[4].Recovered {
		t.Fatalf("post-recovery failure event = %+v", events)
	}
	for _, event := range events {
		if strings.ContainsAny(event.Detail, "\n\r\t") {
			t.Fatalf("diagnostic contains raw control: %+v", event)
		}
	}
}

func TestRuntimeCommandDiagnosticDoesNotChangeCoarseCategory(t *testing.T) {
	validation := &runtimeCommandError{command: "/usr/bin/sway", diagnostic: "swaymsg reload failed", cause: errors.New("exit status 1")}
	if got := runtimeErrorCategory(validation); got != "runtime-validation" {
		t.Fatalf("validator category = %q", got)
	}
	reload := &runtimeCommandError{command: "/usr/bin/swaymsg", diagnostic: "validator output", cause: errors.New("exit status 1")}
	if got := runtimeErrorCategory(reload); got != "runtime-reload" {
		t.Fatalf("reload category = %q", got)
	}
}
