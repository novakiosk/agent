package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/operations"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rotationFixture struct {
	connections atomic.Int32
	t           *testing.T
	mu          sync.Mutex
	state       State
	old         Identity
	transcript  *RotationTranscript
	result      *RotationResult
	activated   bool
	drop        string
	dropped     bool
	now         time.Time
}

func (f *rotationFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.connections.Add(1)
	c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	// Tests keep one active request loop at a time, but old-session cleanup may
	// overlap replacement dial. Protect the durable fake server state throughout.
	f.mu.Lock()
	defer f.mu.Unlock()
	var hello struct {
		Version           int    `json:"version"`
		Type              string `json:"type"`
		EnrollmentID      string `json:"enrollmentId"`
		DeviceID          string `json:"deviceId"`
		PublicIdentityRef string `json:"publicIdentityRef"`
	}
	if c.ReadJSON(&hello) != nil {
		return
	}
	replacement := hello.PublicIdentityRef != f.old.PublicIdentityRef
	if replacement && (f.result == nil || hello.PublicIdentityRef != f.transcript.NewPublicIdentityRef) {
		c.WriteJSON(map[string]any{"version": 1, "type": "session.rejected", "code": "IDENTITY_NOT_APPROVED"})
		return
	}
	if !replacement && f.activated {
		c.WriteJSON(map[string]any{"version": 1, "type": "session.rejected", "code": "IDENTITY_REVOKED"})
		return
	}
	binding := f.state.IdentityBindingID
	if replacement {
		binding = f.transcript.NewBindingID
	}
	challenge := sessionChallenge{Version: 1, Type: "session.challenge", Profile: identityProfile(hello.PublicIdentityRef), SessionID: randomRotationID(), ChallengeID: randomRotationID(), EnrollmentID: f.state.EnrollmentID, IdentityBindingID: binding, DeviceID: f.state.DeviceID, PublicIdentityRef: hello.PublicIdentityRef, Nonce: randomRotationID(), Audience: f.state.InstanceURL, ExpiresAt: f.now.Add(time.Minute).Format(time.RFC3339Nano)}
	if c.WriteJSON(challenge) != nil {
		return
	}
	var proof ChallengeResponse
	if c.ReadJSON(&proof) != nil {
		return
	}
	if !VerifySignature(hello.PublicIdentityRef, ChallengeCanonical(proof), proof.Signature) {
		f.t.Error("invalid session proof")
		return
	}
	if replacement {
		f.activated = true
		if f.drop == "activation" && !f.dropped {
			f.dropped = true
			return
		}
	}
	accepted := sessionAccepted{Version: 1, Type: "session.accepted", Profile: challenge.Profile, SessionID: challenge.SessionID, EnrollmentID: f.state.EnrollmentID, IdentityBindingID: binding, DeviceID: f.state.DeviceID}
	if c.WriteJSON(accepted) != nil {
		return
	}
	for {
		var raw json.RawMessage
		if c.ReadJSON(&raw) != nil {
			return
		}
		var envelope rotationEnvelope
		json.Unmarshal(raw, &envelope)
		if envelope.SessionID != accepted.SessionID || envelope.DeviceID != f.state.DeviceID || envelope.Profile != accepted.Profile {
			f.t.Error("rotation request binding mismatch")
			return
		}
		switch envelope.Type {
		case "identity.rotation.prepare":
			var prepare rotationPrepare
			if decodeStrict(raw, &prepare) != nil {
				return
			}
			if f.transcript == nil {
				f.transcript = &RotationTranscript{Version: 1, Audience: f.state.InstanceURL, DeviceID: f.state.DeviceID, EnrollmentID: f.state.EnrollmentID, TransitionID: prepare.TransitionID, OldBindingID: f.state.IdentityBindingID, NewBindingID: "new-binding", OldProfile: f.old.Profile(), NewProfile: P256IdentityProfile, OldPublicIdentityRef: f.old.PublicIdentityRef, NewPublicIdentityRef: prepare.NewPublicIdentityRef, OldGeneration: f.old.Generation, NewGeneration: f.old.Generation + 1, OldBacking: "unknown", NewBacking: prepare.NewBacking, Nonce: randomRotationID(), IssuedAt: f.now.Format("2006-01-02T15:04:05.000Z"), ExpiresAt: f.now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")}
			}
			if f.drop == "prepare" && !f.dropped {
				f.dropped = true
				return
			}
			envelope.Type = "identity.rotation.prepared"
			if c.WriteJSON(rotationPrepared{envelope, *f.transcript}) != nil {
				return
			}
		case "identity.rotation.commit":
			var commit rotationCommit
			if decodeStrict(raw, &commit) != nil {
				return
			}
			canonical := RotationCanonical(*f.transcript)
			if !VerifySignature(f.old.PublicIdentityRef, canonical, commit.OldSignature) || !VerifySignature(f.transcript.NewPublicIdentityRef, canonical, commit.NewSignature) {
				f.t.Error("invalid dual proof")
				return
			}
			if f.result == nil {
				f.result = &RotationResult{TransitionID: f.transcript.TransitionID, EnrollmentID: f.state.EnrollmentID, DeviceID: f.state.DeviceID, OldBindingID: f.state.IdentityBindingID, NewBindingID: f.transcript.NewBindingID, NewPublicIdentityRef: f.transcript.NewPublicIdentityRef, NewGeneration: f.transcript.NewGeneration, NewBacking: f.transcript.NewBacking, CommittedAt: f.now.Format("2006-01-02T15:04:05.000Z"), OverlapExpiresAt: f.now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")}
			}
			if f.drop == "commit" && !f.dropped {
				f.dropped = true
				return
			}
			envelope.Type = "identity.rotation.committed"
			if c.WriteJSON(rotationCommitted{envelope, *f.result}) != nil {
				return
			}
		case "identity.rotation.status":
			if f.drop == "status" && !f.dropped {
				f.dropped = true
				return
			}
			at := f.now.Format("2006-01-02T15:04:05.000Z")
			envelope.Type = "identity.rotation.status.result"
			if c.WriteJSON(rotationStatus{envelope, "activated", *f.transcript, f.result, &at}) != nil {
				return
			}
		default:
			f.t.Errorf("rotation client executed unrelated operation %s", envelope.Type)
			return
		}
	}
}
func newRotationFixture(t *testing.T, p256 bool) (*rotationFixture, Client) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	var identity Identity
	var err error
	if p256 {
		identity, err = CreateSoftwareIdentity(dir, "opaque-existing-device")
	} else {
		identity, err = GenerateIdentity()
		if err == nil {
			err = SaveIdentityAtomic(dir, identity)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	fixture := &rotationFixture{t: t, old: identity, now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	server, ca := trustedTLSServer(t, http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	fixture.state = State{Version: 1, Status: "Managed", InstanceURL: server.URL, EnrollmentID: "existing-enrollment", DeviceID: identity.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, IdentityBindingID: "old-binding", SessionID: "old-session", HeartbeatSequence: 57, LastHeartbeatAt: "2026-10-05T11:59:00Z", PrinterReportSequence: 21, FleetUpdateSequence: 42}
	if err := SaveStateAtomic(dir, fixture.state); err != nil {
		t.Fatal(err)
	}
	return fixture, Client{StateDir: dir, CAPath: ca, Now: func() time.Time { return fixture.now }}
}
func TestRotationRecoversDurableBoundariesAndLostReplies(t *testing.T) {
	for _, p256 := range []bool{false, true} {
		for _, stop := range []string{"", "candidate", "prepared", "committed", "activated", "identity", "state", "prepare-reply", "commit-reply", "activation-reply", "status-reply"} {
			t.Run(fmt.Sprintf("p256=%v/%s", p256, stop), func(t *testing.T) {
				fixture, client := newRotationFixture(t, p256)
				if len(stop) > 6 && stop[len(stop)-6:] == "-reply" {
					fixture.drop = stop[:len(stop)-6]
				} else if stop != "" {
					client.rotationCheckpoint = func(boundary string) error {
						if boundary == stop {
							return errors.New("injected process stop")
						}
						return nil
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := client.RotateIdentity(ctx, SoftwareP256)
				if stop != "" {
					if err == nil {
						t.Fatal("failure injection did not stop rotation")
					}
					if err := RequireOrdinaryAuthority(client.StateDir); !errors.Is(err, ErrIdentity) {
						t.Fatal("daemon admitted unfinished transition")
					}
					var journal rotationJournal
					data, e := readPrivateRecord(client.StateDir, rotationFilename, maxRotationBytes)
					if e != nil || json.Unmarshal(data, &journal) != nil {
						t.Fatal("durable candidate missing")
					}
					candidate := string(journal.Candidate)
					transition := journal.TransitionID
					client.rotationCheckpoint = nil
					if err := client.RotateIdentity(ctx, SoftwareP256); err != nil {
						t.Fatal(err)
					}
					final, _ := os.ReadFile(IdentityPath(client.StateDir))
					if string(final) != candidate || fixture.transcript.TransitionID != transition {
						t.Fatal("recovery replaced candidate/transition")
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if err := RequireOrdinaryAuthority(client.StateDir); err != nil {
					t.Fatal(err)
				}
				state, err := LoadState(client.StateDir)
				if err != nil {
					t.Fatal(err)
				}
				identity, err := LoadIdentity(client.StateDir)
				if err != nil {
					t.Fatal(err)
				}
				defer identity.Close()
				if !fixture.activated || state.IdentityBindingID != "new-binding" || state.PublicIdentityRef != identity.PublicIdentityRef || state.HeartbeatSequence != 57 || state.PrinterReportSequence != 21 || state.FleetUpdateSequence != 42 || state.DeviceID != fixture.state.DeviceID || state.EnrollmentID != fixture.state.EnrollmentID || identity.Generation != fixture.old.Generation+1 {
					t.Fatal("rotation lost authority association or counters")
				}
			})
		}
	}
}

func TestRotationAndMigrationRejectUnresolvedOperationsWithoutRecovery(t *testing.T) {
	for _, phase := range []operations.JournalPhase{operations.PhaseAccepted, operations.PhaseExecutionStarted, operations.PhaseExecuted, operations.PhaseResultAccepted} {
		t.Run(string(phase), func(t *testing.T) {
			fixture, client := newRotationFixture(t, false)
			command := operations.Command{Version: 1, Type: operations.CommandMessageType, CommandID: "00112233-4455-4677-8899-aabbccddeeff", CommandType: operations.CommandReboot, IssuedAt: fixture.now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: fixture.now.Add(time.Minute).Format(time.RFC3339Nano)}
			command.PayloadHash, _ = command.CanonicalPayloadHash()
			journal := map[string]any{"version": 1, "type": operations.OperationJournalType, "phase": phase, "command": command}
			if phase == operations.PhaseExecuted || phase == operations.PhaseResultAccepted {
				journal["result"] = operations.OperationResult{Version: 1, Type: operations.OperationType, CommandType: operations.CommandReboot, Result: operations.ResultScheduled, ObservedAt: fixture.now.Format(time.RFC3339Nano)}
			}
			data, _ := json.Marshal(journal)
			path := operations.OperationJournalPath(client.StateDir)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if phase == operations.PhaseResultAccepted {
				if err := operations.RequireResolvedForRotation(client.StateDir, fixture.now); err != nil {
					t.Fatal(err)
				}
				if err := operations.ValidateResolvedJournal(data, fixture.now); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err := operations.ValidateResolvedJournal(data, fixture.now); err == nil {
				t.Fatal("migration accepted unresolved operation")
			}
			if err := client.RotateIdentity(context.Background(), SoftwareP256); err == nil {
				t.Fatal("rotation accepted unresolved operation")
			}
			if _, err := os.Stat(filepath.Join(client.StateDir, rotationFilename)); !os.IsNotExist(err) {
				t.Fatal("rotation staged candidate for unresolved operation")
			}
			if fixture.connections.Load() != 0 {
				t.Fatal("rotation contacted server before operation resolution")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(data, after) {
				t.Fatal("readonly preflight rewrote/recovered operation journal")
			}
		})
	}
}
