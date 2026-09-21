package enrollment

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestValidateSessionChallengeRejectsAudienceAndExpiryMismatch(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := validateInstance("https://CONTROL.example/")
	if err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Status: "Managed", InstanceURL: instance.String(), EnrollmentID: "enrollment-01", DeviceID: "device-01"}
	base := sessionChallenge{Version: 1, Type: "session.challenge", Profile: ProvisionalIdentityProfile, SessionID: "session-01", ChallengeID: "challenge-01", EnrollmentID: state.EnrollmentID, IdentityBindingID: "binding-01", DeviceID: state.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, Nonce: "nonce-01", Audience: instance.String(), ExpiresAt: "2099-01-01T00:00:00Z"}
	if err := validateSessionChallenge(base, state, identity, instance, time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	wrongAudience := base
	wrongAudience.Audience += "/"
	if err := validateSessionChallenge(wrongAudience, state, identity, instance, time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("challenge with non-canonical audience was accepted")
	}
	expired := base
	expired.ExpiresAt = "2020-01-01T00:00:00Z"
	if err := validateSessionChallenge(expired, state, identity, instance, time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired challenge error = %v", err)
	}
}

func TestReadSessionMessageHasBoundedDeadline(t *testing.T) {
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{}
		connection, err := upgrader.Upgrade(response, request, nil)
		if err != nil {
			return
		}
		_, _, _ = connection.ReadMessage()
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("bounded read integration requires a network socket: %v", err)
		}
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	endpoint := "ws://" + listener.Addr().String()
	connection, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	started := time.Now()
	readContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = readSessionMessage(readContext, connection, &struct{}{})
	if err == nil {
		t.Fatal("unbounded session read unexpectedly returned success")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("session read exceeded bound: %s", elapsed)
	}
}

func validateDesiredSnapshot(snapshot DesiredSnapshot, sessionID, deviceID string) error {
	return validateDesiredSnapshotAt(snapshot, sessionID, deviceID, time.Now(), false, false)
}

func validateDesiredSnapshotWithReplay(snapshot DesiredSnapshot, sessionID, deviceID string, allowExpiredOperation bool) error {
	return validateDesiredSnapshotAt(snapshot, sessionID, deviceID, time.Now(), allowExpiredOperation, false)
}
