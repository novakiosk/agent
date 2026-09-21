package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBrowserExpiryIsIndependentOfOperationReplay(t *testing.T) {
	command := browserCommandFixture("reload", nil)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	snapshot := DesiredSnapshot{Version: ProtocolVersion, Type: "desired.snapshot", SessionID: "session-1", DeviceID: "device-1", BrowserCommand: command}
	if err := validateDesiredSnapshotAt(snapshot, snapshot.SessionID, snapshot.DeviceID, now, true, false); err == nil {
		t.Fatal("operation replay admitted an expired browser command")
	}
	if err := validateDesiredSnapshotAt(snapshot, snapshot.SessionID, snapshot.DeviceID, now, false, true); err != nil {
		t.Fatalf("saved browser result cannot replay after expiry: %v", err)
	}
	client := Client{Now: func() time.Time { return now }}
	state := State{}
	// Admission can precede slow runtime work; execution must check expiry again.
	if err := client.applyBrowserCommand(t.Context(), &state, Identity{}, nil, nil, nil, "", snapshot, nil, nil, nil, nil); err == nil {
		t.Fatal("expired command reached the browser")
	}
	if state.LastBrowserCommandID != "" {
		t.Fatal("expired new command changed replay state")
	}
}

func TestRunReplaysExpiredBrowserResultWithoutOperation(t *testing.T) {
	fixture, client, _ := newRunFixture(t, false, false)
	command := browserCommandFixture("reload", nil)
	command.IssuedAt, command.ExpiresAt = "2026-08-24T11:00:00Z", "2026-08-24T11:14:00Z"
	command.PayloadHash = BrowserCommandHash(*command)
	fixture.browserCommand = command
	state := fixture.state
	state.LastBrowserCommandID, state.LastBrowserCommandHash = command.CommandID, command.PayloadHash
	state.LastBrowserCommandResult, state.LastBrowserCommandAt = "applied", "2026-08-24T11:01:00Z"
	state.LastBrowserCommandObservedURL, state.BrowserCommandSequence = "https://example.test/previous", 1
	if err := SaveStateAtomic(client.StateDir, state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx, RunOptions{BrowserFactory: func(context.Context, string) (Browser, error) { return NewFakeBrowser(nil), nil }})
	}()
	select {
	case result := <-fixture.browserCommandResults:
		if result.Sequence != 1 || result.ObservedURL != state.LastBrowserCommandObservedURL || result.ObservedAt != state.LastBrowserCommandAt {
			t.Errorf("saved browser result was not replayed: %+v", result)
		}
	case err := <-done:
		t.Fatalf("run stopped before replay: %v", err)
	case <-ctx.Done():
		t.Fatal("expired browser result was not replayed")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run cancellation: %v", err)
	}
}

func TestBrowserCommandHashAndValidation(t *testing.T) {
	zoom := 125
	command := BrowserCommand{Version: ProtocolVersion, Type: BrowserCommandType, Profile: ProvisionalIdentityProfile, CommandID: "11111111-1111-4111-8111-111111111111", Action: "set-zoom", ZoomPercent: &zoom, IssuedAt: "2026-08-31T10:00:00Z", ExpiresAt: "2026-08-31T10:15:00Z"}
	command.PayloadHash = BrowserCommandHash(command)
	if err := command.Validate(time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC), false); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	zoom = 126
	command.PayloadHash = BrowserCommandHash(command)
	if err := command.Validate(time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC), false); err == nil {
		t.Fatal("unallowed zoom accepted")
	}
}

func TestBrowserCommandResultValidation(t *testing.T) {
	result := BrowserCommandResult{Version: ProtocolVersion, Type: BrowserCommandResultType, Profile: ProvisionalIdentityProfile, SessionID: "session-1", DeviceID: "device-1", CommandID: "11111111-1111-4111-8111-111111111111", Action: "reload", PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Result: "applied", ObservedAt: "2026-08-31T10:01:00Z", Sequence: 1}
	if err := result.Validate(); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	errorCategory := "browser-zoom"
	result.ErrorCategory = &errorCategory
	if err := result.Validate(); err == nil {
		t.Fatal("applied result with error accepted")
	}
	result = BrowserCommandResult{Version: ProtocolVersion, Type: BrowserCommandResultType, Profile: ProvisionalIdentityProfile, SessionID: "session-1", DeviceID: "device-1", CommandID: "11111111-1111-4111-8111-111111111111", Action: "set-zoom", PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Result: "failed", ErrorCategory: &errorCategory, ObservedAt: "2026-08-31T10:01:00Z", Sequence: 1}
	if err := result.Validate(); err != nil {
		t.Fatalf("failed set-zoom result without accepted zoom rejected: %v", err)
	}
	zoom := 125
	result.ZoomPercent = &zoom
	if err := result.Validate(); err == nil {
		t.Fatal("failed set-zoom result with accepted zoom accepted")
	}
}

func TestBrowserCommandTimestampUsesRFC3339NanoCanonicalForms(t *testing.T) {
	valid := []string{
		"2026-08-31T10:01:00Z",
		"2026-08-31T10:01:00.1Z",
		"2026-08-31T10:01:00.12Z",
		"2026-08-31T10:01:00.123Z",
		"2026-08-31T10:01:00.1234Z",
		"2026-08-31T10:01:00.123456789Z",
	}
	for _, timestamp := range valid {
		if _, err := parseBrowserCommandTimestamp(timestamp); err != nil {
			t.Errorf("canonical timestamp %q rejected: %v", timestamp, err)
		}
	}
	invalid := []string{
		"2026-08-31T10:01:00.0Z",
		"2026-08-31T10:01:00.120Z",
		"2026-08-31T10:01:00.1230Z",
		"2026-08-31T10:01:00.000Z",
		"2026-08-31T10:01:00.1234567890Z",
	}
	for _, timestamp := range invalid {
		if _, err := parseBrowserCommandTimestamp(timestamp); err == nil {
			t.Errorf("non-canonical timestamp %q accepted", timestamp)
		}
	}
}
