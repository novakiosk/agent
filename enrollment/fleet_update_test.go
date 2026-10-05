package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/operations"
)

func TestFleetSharedP256Canonical(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/fleet-update-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Report                     FleetUpdateReport
		ReportCanonical, PublicKey string
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture")
	}
	canonical := FleetUpdateCanonical(f.Report)
	if string(canonical) != f.ReportCanonical {
		t.Fatal("Go/TS canonical mismatch")
	}
	block, _ := pem.Decode([]byte(f.PublicKey))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(f.Report.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), sum[:], signature) {
		t.Fatal("TS report signature rejected")
	}
	f.Report.Boot.Release.ImageDigest = "tampered"
	sum = sha256.Sum256(FleetUpdateCanonical(f.Report))
	if ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), sum[:], signature) {
		t.Fatal("altered binary accepted")
	}
}

type reportFleet struct {
	boot    operations.BootRelease
	effects int
}

func (f *reportFleet) Observe(context.Context) (operations.BootRelease, string, error) {
	return f.boot, "", nil
}
func (f *reportFleet) Active(context.Context) (bool, error)                  { return false, nil }
func (f *reportFleet) Stage(context.Context, operations.UpdateCommand) error { f.effects++; return nil }
func (f *reportFleet) Reboot(context.Context) error                          { f.effects++; return nil }
func TestFleetLostACKReconnectReplaysTerminal(t *testing.T) {
	raw, _ := os.ReadFile("../fixtures/fleet-update-v1.json")
	var fixture struct{ Command operations.UpdateCommand }
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	identity, err := CreateSoftwareIdentity(dir, "device-one")
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, fixture.Command.IssuedAt)
	client := Client{StateDir: dir, Now: func() time.Time { return now }}
	f := &reportFleet{boot: operations.BootRelease{UpdateMode: "automatic", BootID: fixture.Command.BootIDBefore, Release: fixture.Command.Release}}
	fleet, err := operations.NewFleetCoordinator(dir, f, client.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = fleet.Accept(fixture.Command); err != nil {
		t.Fatal(err)
	}
	if err = fleet.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	power, err := operations.NewCoordinator(operations.CoordinatorConfig{StateDir: dir, Executor: operations.NewExecutor(operations.OperationConfig{}), Clock: client.now})
	if err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Status: "Managed", InstanceURL: "https://control.example", EnrollmentID: "enrollment-one", IdentityBindingID: "binding-one", HeartbeatSequence: 1, LastHeartbeatAt: now.Format(time.RFC3339), DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, SessionID: "session-one"}
	sequences := make(chan uint64, 2)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var report FleetUpdateReport
		if conn.ReadJSON(&report) != nil {
			return
		}
		if !verifyP256Test(identity.PublicIdentityRef, FleetUpdateCanonical(report), report.Signature) {
			t.Error("bad signed report")
		}
		sequences <- report.Sequence
		if r.URL.Path == "/lost" {
			return
		}
		_ = conn.WriteJSON(map[string]any{"version": 1, "type": "fleet-update.accepted", "sessionId": report.SessionID, "deviceId": report.DeviceID, "commandId": report.CommandID, "sequence": report.Sequence, "disposition": "accepted"})
	}))
	defer server.Close()
	for i, path := range []string{"/lost", "/ack"} {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[4:]+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = client.handleFleetUpdate(context.Background(), &state, identity, conn, nil, fleet, power, time.Second, nil)
		conn.Close()
		if i == 0 {
			if err == nil || !fleet.Busy() {
				t.Fatal("lost ACK resolved update")
			}
			state.SessionID = "session-two"
			fleet, err = operations.NewFleetCoordinator(dir, f, client.now)
			if err != nil {
				t.Fatal(err)
			}
		} else if err != nil || fleet.Busy() {
			t.Fatal("replay failed", err)
		}
	}
	if first, second := <-sequences, <-sequences; first != 1 || second != 2 {
		t.Fatal("counter not advanced")
	}
	persisted, err := LoadState(dir)
	if err != nil || persisted.FleetUpdateSequence != 2 || f.effects != 0 {
		t.Fatal("counter/effect replay", err)
	}
}

func TestFleetMigrationAndResetGuard(t *testing.T) {
	raw, _ := os.ReadFile("../fixtures/fleet-update-v1.json")
	var fixture struct{ Command operations.UpdateCommand }
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	// Use a past accepted command: delivery expiry cannot make unfinished work
	// safe to discard at an authority boundary.
	fixture.Command.IssuedAt = "2026-01-01T00:00:00Z"
	fixture.Command.ExpiresAt = "2026-01-01T00:02:00Z"
	fixture.Command.ObserveUntil = "2026-01-01T01:00:00Z"
	fixture.Command.PayloadHash = fixture.Command.Hash()
	for _, resolved := range []bool{false, true} {
		t.Run(fmt.Sprint(resolved), func(t *testing.T) {
			source, _ := legacyMigrationFixture(t)
			reason := "stage_not_pending"
			journal := operations.FleetJournal{Version: 1, Command: fixture.Command, Phase: "failed", Error: &reason, Acknowledged: resolved}
			raw, _ := json.Marshal(journal)
			if err := os.WriteFile(filepath.Join(source, operations.FleetJournalName), raw, 0600); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(t.TempDir(), "migrated")
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			err := migrateAuthorityAt(source, destination, "kiosk", "https://control.example", uid, uid, gid)
			if (err == nil) != resolved {
				t.Fatal("migration guard", err)
			}
			err = Reset(source)
			if (err == nil) != resolved {
				t.Fatal("reset guard", err)
			}
			if resolved {
				if _, err := os.Stat(filepath.Join(source, operations.FleetJournalName)); !os.IsNotExist(err) {
					t.Fatal("reset left old authority journal")
				}
			} else {
				if _, err := LoadState(source); err != nil {
					t.Fatal("rejected reset changed state", err)
				}
			}
		})
	}
}

func TestFleetReportCacheIsSessionBoundAndFresh(t *testing.T) {
	now := time.Now()
	cache := &fleetReportCache{session: "one", key: "observation", acknowledgedAt: now}
	if !cache.quiet("one", "observation", now.Add(15*time.Second)) {
		t.Fatal("unchanged report not suppressed")
	}
	for _, tc := range []struct {
		session, key string
		at           time.Time
	}{{"two", "observation", now}, {"one", "executing", now}, {"one", "observation", now.Add(time.Minute)}, {"one", "observation", now.Add(-time.Second)}} {
		if cache.quiet(tc.session, tc.key, tc.at) {
			t.Fatal("changed/stale evidence suppressed")
		}
	}
}
