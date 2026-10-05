package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/operations"
)

func (client Client) rotationBoundary(name string) error {
	if client.rotationCheckpoint != nil {
		return client.rotationCheckpoint(name)
	}
	return nil
}
func randomRotationID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return encodeRaw(b[:])
}

type rotationEnvelope struct {
	Version      int    `json:"version"`
	Type         string `json:"type"`
	Profile      string `json:"profile"`
	SessionID    string `json:"sessionId"`
	DeviceID     string `json:"deviceId"`
	TransitionID string `json:"transitionId"`
}
type rotationPrepare struct {
	rotationEnvelope
	NewPublicIdentityRef string `json:"newPublicIdentityRef"`
	NewBacking           string `json:"newBacking"`
}
type rotationCommit struct {
	rotationEnvelope
	OldSignature string `json:"oldSignature"`
	NewSignature string `json:"newSignature"`
}
type rotationPrepared struct {
	rotationEnvelope
	Transcript RotationTranscript `json:"transcript"`
}
type rotationCommitted struct {
	rotationEnvelope
	Result RotationResult `json:"result"`
}
type rotationStatus struct {
	rotationEnvelope
	State       string             `json:"state"`
	Transcript  RotationTranscript `json:"transcript"`
	Result      *RotationResult    `json:"result"`
	ActivatedAt *string            `json:"activatedAt"`
}
type rotationRejected struct {
	rotationEnvelope
	Code string `json:"code"`
}

func readRotationReply(ctx context.Context, connection *websocket.Conn, expected rotationEnvelope, destination any) error {
	for range 8 {
		var raw json.RawMessage
		if err := readSessionMessage(ctx, connection, &raw); err != nil {
			return err
		}
		var header struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &header) != nil {
			return fmt.Errorf("invalid rotation reply")
		}
		if header.Type == "desired.snapshot" {
			continue
		} // never execute temporary-session commands
		if header.Type == "identity.rotation.rejected" {
			var rejected rotationRejected
			if decodeStrict(raw, &rejected) != nil {
				return fmt.Errorf("invalid rotation rejection")
			}
			want := expected
			want.Type = header.Type
			if rejected.rotationEnvelope != want {
				return fmt.Errorf("rotation rejection authority mismatch")
			}
			return fmt.Errorf("rotation rejected: %s", rejected.Code)
		}
		if header.Type != expected.Type {
			return fmt.Errorf("unexpected rotation reply")
		}
		if err := decodeStrict(raw, destination); err != nil {
			return err
		}
		var envelope rotationEnvelope
		switch result := destination.(type) {
		case *rotationPrepared:
			envelope = result.rotationEnvelope
		case *rotationCommitted:
			envelope = result.rotationEnvelope
		case *rotationStatus:
			envelope = result.rotationEnvelope
		default:
			return fmt.Errorf("unsupported rotation reply")
		}
		if envelope != expected {
			return fmt.Errorf("rotation reply authority mismatch")
		}
		return nil
	}
	return fmt.Errorf("too many unrelated messages on rotation session")
}
func sessionRotationEnvelope(kind string, accepted sessionAccepted, identity Identity, transition string) rotationEnvelope {
	return rotationEnvelope{Version: 1, Type: kind, Profile: identity.Profile(), SessionID: accepted.SessionID, DeviceID: identity.DeviceID, TransitionID: transition}
}

// RotateIdentity is attended and deliberately does not start any runtime,
// printer or operation handlers. The caller must restart ordinary agentd after
// success. Errors retain the exact journal/candidate for explicit retry.
func (client Client) RotateIdentity(ctx context.Context, backing string) error {
	lock, err := AcquireAuthorityLock(client.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := LoadState(client.StateDir)
	if err != nil {
		return err
	}
	if state.Status != "Managed" {
		return fmt.Errorf("rotation requires approved managed enrollment")
	}
	if err := operations.RequireResolvedForRotation(client.StateDir, client.now()); err != nil {
		return err
	}
	var journal rotationJournal
	data, err := readPrivateRecord(client.StateDir, rotationFilename, maxRotationBytes)
	if errors.Is(err, os.ErrNotExist) {
		oldData, err := readIdentityFile(client.StateDir)
		if err != nil {
			return err
		}
		old, err := decodeIdentityMode(oldData, false)
		if err != nil {
			return err
		}
		if old.DeviceID != state.DeviceID || old.PublicIdentityRef != state.PublicIdentityRef {
			return fmt.Errorf("old identity does not match managed state")
		}
		if backing == "" {
			backing, err = SelectFreshBacking("auto")
			if err != nil {
				return err
			}
		}
		candidate, candidateData, err := newP256Identity(old.DeviceID, backing, old.Generation+1)
		if err != nil {
			return err
		}
		candidate.Close()
		journal = rotationJournal{Version: 1, TransitionID: randomRotationID(), InstanceURL: state.InstanceURL, EnrollmentID: state.EnrollmentID, OldBindingID: state.IdentityBindingID, OldIdentity: oldData, Candidate: candidateData}
		if err := saveRotation(client.StateDir, journal); err != nil {
			return err
		}
		if err := client.rotationBoundary("candidate"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if decodeStrictBounded(data, &journal, maxRotationBytes) != nil {
		return fmt.Errorf("invalid rotation journal")
	}
	active, err := readIdentityFile(client.StateDir)
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, active); err != nil {
		return fmt.Errorf("invalid active identity")
	}
	var oldCompact, candidateCompact bytes.Buffer
	if json.Compact(&oldCompact, journal.OldIdentity) != nil || json.Compact(&candidateCompact, journal.Candidate) != nil {
		return fmt.Errorf("invalid journal identity")
	}
	if !bytes.Equal(compact.Bytes(), oldCompact.Bytes()) && !bytes.Equal(compact.Bytes(), candidateCompact.Bytes()) {
		return fmt.Errorf("active identity differs from durable rotation journal")
	}
	oldMeta, err := decodeIdentityMode(journal.OldIdentity, false)
	if err != nil {
		return err
	}
	candidateMeta, err := decodeIdentityMode(journal.Candidate, false)
	if err != nil {
		return err
	}
	if journal.Version != 1 || journal.InstanceURL != state.InstanceURL || journal.EnrollmentID != state.EnrollmentID || journal.OldBindingID == "" || candidateMeta.DeviceID != state.DeviceID || oldMeta.DeviceID != state.DeviceID || candidateMeta.Generation != oldMeta.Generation+1 || candidateMeta.PublicIdentityRef == oldMeta.PublicIdentityRef || candidateMeta.Profile() != P256IdentityProfile {
		return fmt.Errorf("rotation journal authority mismatch")
	}
	if _, err := decodeRaw(journal.TransitionID, 32); err != nil {
		return err
	}
	if backing != "" && candidateMeta.Backing != backing {
		return fmt.Errorf("resume must retain original candidate backing")
	}
	if state.PublicIdentityRef != oldMeta.PublicIdentityRef && state.PublicIdentityRef != candidateMeta.PublicIdentityRef {
		return fmt.Errorf("rotation journal does not match active bundle")
	}
	oldState := state
	oldState.PublicIdentityRef = oldMeta.PublicIdentityRef
	oldState.IdentityBindingID = journal.OldBindingID
	if journal.Transcript != nil {
		if err := journal.Transcript.validate(oldState, oldMeta, candidateMeta, journal.TransitionID, client.now(), true); err != nil {
			return err
		}
	}
	if journal.Result != nil {
		if journal.Transcript == nil {
			return fmt.Errorf("rotation result has no transcript")
		}
		if err := journal.Result.validate(*journal.Transcript); err != nil {
			return err
		}
	}
	candidate, err := decodeIdentity(journal.Candidate)
	if err != nil {
		return fmt.Errorf("%w: candidate load: %v", ErrIdentity, err)
	}
	defer candidate.Close()
	if journal.Transcript != nil {
		activated, err := client.activateRotation(ctx, state, candidate, journal)
		if err == nil {
			return client.finishRotation(state, candidate, journal, activated)
		}
		var rejected *SessionProtocolError
		if !errors.As(err, &rejected) || rejected.Code != "IDENTITY_NOT_APPROVED" {
			return err
		}
		if journal.Result != nil {
			return fmt.Errorf("committed candidate is unexpectedly unapproved; attended server recovery required")
		}
	}
	old, err := decodeIdentity(journal.OldIdentity)
	if err != nil {
		return fmt.Errorf("%w: old signer load: %v", ErrIdentity, err)
	}
	defer old.Close()
	connection, accepted, cleanup, err := client.openManagedSession(ctx, oldState, old, sessionMessageTimeout)
	if err != nil {
		return err
	}
	defer cleanup()
	if accepted.IdentityBindingID != journal.OldBindingID {
		return fmt.Errorf("old session binding mismatch")
	}
	prepare := rotationPrepare{rotationEnvelope: sessionRotationEnvelope("identity.rotation.prepare", accepted, old, journal.TransitionID), NewPublicIdentityRef: candidate.PublicIdentityRef, NewBacking: candidate.Backing}
	if err := writeSessionMessage(connection, prepare, sessionMessageTimeout); err != nil {
		return err
	}
	expected := prepare.rotationEnvelope
	expected.Type = "identity.rotation.prepared"
	var prepared rotationPrepared
	if err := readRotationReply(ctx, connection, expected, &prepared); err != nil {
		return err
	}
	if err := prepared.Transcript.validate(oldState, old, candidate, journal.TransitionID, client.now(), false); err != nil {
		return err
	}
	if journal.Transcript != nil && *journal.Transcript != prepared.Transcript {
		return fmt.Errorf("server replaced the original rotation transcript")
	}
	journal.Transcript = &prepared.Transcript
	if err := saveRotation(client.StateDir, journal); err != nil {
		return err
	}
	if err := client.rotationBoundary("prepared"); err != nil {
		return err
	}
	canonical := RotationCanonical(prepared.Transcript)
	oldProof, err := old.sign(canonical)
	if err != nil {
		return err
	}
	newProof, err := candidate.sign(canonical)
	if err != nil {
		return err
	}
	commit := rotationCommit{rotationEnvelope: sessionRotationEnvelope("identity.rotation.commit", accepted, old, journal.TransitionID), OldSignature: oldProof, NewSignature: newProof}
	if err := writeSessionMessage(connection, commit, sessionMessageTimeout); err != nil {
		return err
	}
	expected = commit.rotationEnvelope
	expected.Type = "identity.rotation.committed"
	var committed rotationCommitted
	if err := readRotationReply(ctx, connection, expected, &committed); err != nil {
		return err
	}
	if err := committed.Result.validate(prepared.Transcript); err != nil {
		return err
	}
	journal.Result = &committed.Result
	if err := saveRotation(client.StateDir, journal); err != nil {
		return err
	}
	if err := client.rotationBoundary("committed"); err != nil {
		return err
	}
	cleanup()
	old.Close()
	activated, err := client.activateRotation(ctx, state, candidate, journal)
	if err != nil {
		return err
	}
	return client.finishRotation(state, candidate, journal, activated)
}
func (client Client) activateRotation(ctx context.Context, state State, candidate Identity, journal rotationJournal) (sessionAccepted, error) {
	state.PublicIdentityRef = candidate.PublicIdentityRef
	state.IdentityBindingID = journal.Transcript.NewBindingID
	connection, accepted, cleanup, err := client.openManagedSession(ctx, state, candidate, sessionMessageTimeout)
	if err != nil {
		return sessionAccepted{}, err
	}
	defer cleanup()
	if accepted.IdentityBindingID != journal.Transcript.NewBindingID {
		return sessionAccepted{}, fmt.Errorf("replacement session binding mismatch")
	}
	request := sessionRotationEnvelope("identity.rotation.status", accepted, candidate, journal.TransitionID)
	if err := writeSessionMessage(connection, request, sessionMessageTimeout); err != nil {
		return sessionAccepted{}, err
	}
	expected := request
	expected.Type = "identity.rotation.status.result"
	var status rotationStatus
	if err := readRotationReply(ctx, connection, expected, &status); err != nil {
		return sessionAccepted{}, err
	}
	if status.State != "activated" || status.Result == nil || status.ActivatedAt == nil || status.Transcript != *journal.Transcript {
		return sessionAccepted{}, fmt.Errorf("replacement activation not confirmed")
	}
	if _, err := rotationTimestamp(*status.ActivatedAt); err != nil {
		return sessionAccepted{}, err
	}
	if err := status.Result.validate(status.Transcript); err != nil {
		return sessionAccepted{}, err
	}
	if journal.Result != nil && *journal.Result != *status.Result {
		return sessionAccepted{}, fmt.Errorf("rotation result changed")
	}
	journal.Result = status.Result
	if err := saveRotation(client.StateDir, journal); err != nil {
		return sessionAccepted{}, err
	}
	if err := client.rotationBoundary("activated"); err != nil {
		return sessionAccepted{}, err
	}
	return accepted, nil
}
func (client Client) finishRotation(state State, candidate Identity, journal rotationJournal, accepted sessionAccepted) error {
	if err := writePrivateRecord(client.StateDir, identityFilename, journal.Candidate); err != nil {
		return err
	}
	if err := client.rotationBoundary("identity"); err != nil {
		return err
	}
	state.PublicIdentityRef = candidate.PublicIdentityRef
	state.IdentityBindingID = accepted.IdentityBindingID
	state.SessionID = accepted.SessionID
	// Evidence counters and assignment/operation journals remain enrollment-scoped.
	if err := SaveStateAtomic(client.StateDir, state); err != nil {
		return err
	}
	if err := client.rotationBoundary("state"); err != nil {
		return err
	}
	if err := removePrivateRecord(client.StateDir, migrationFilename); err != nil {
		return err
	}
	return removePrivateRecord(client.StateDir, rotationFilename)
}
