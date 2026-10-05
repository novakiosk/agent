package enrollment

import (
	"fmt"
	"strconv"
	"time"
)

// RotationTranscript binds both proofs to one server-issued transition. Backing
// is a local declaration, not a TPM attestation.
type RotationTranscript struct {
	Version              int    `json:"version"`
	Audience             string `json:"audience"`
	DeviceID             string `json:"deviceId"`
	EnrollmentID         string `json:"enrollmentId"`
	TransitionID         string `json:"transitionId"`
	OldBindingID         string `json:"oldBindingId"`
	NewBindingID         string `json:"newBindingId"`
	OldProfile           string `json:"oldProfile"`
	NewProfile           string `json:"newProfile"`
	OldPublicIdentityRef string `json:"oldPublicIdentityRef"`
	NewPublicIdentityRef string `json:"newPublicIdentityRef"`
	OldGeneration        uint64 `json:"oldGeneration"`
	NewGeneration        uint64 `json:"newGeneration"`
	OldBacking           string `json:"oldBacking"`
	NewBacking           string `json:"newBacking"`
	Nonce                string `json:"nonce"`
	IssuedAt             string `json:"issuedAt"`
	ExpiresAt            string `json:"expiresAt"`
}
type RotationResult struct {
	TransitionID         string `json:"transitionId"`
	EnrollmentID         string `json:"enrollmentId"`
	DeviceID             string `json:"deviceId"`
	OldBindingID         string `json:"oldBindingId"`
	NewBindingID         string `json:"newBindingId"`
	NewPublicIdentityRef string `json:"newPublicIdentityRef"`
	NewGeneration        uint64 `json:"newGeneration"`
	NewBacking           string `json:"newBacking"`
	CommittedAt          string `json:"committedAt"`
	OverlapExpiresAt     string `json:"overlapExpiresAt"`
}

func RotationCanonical(t RotationTranscript) []byte {
	return CanonicalV1("identity.rotation",
		CanonicalField{"version", strconv.Itoa(t.Version)}, CanonicalField{"audience", t.Audience},
		CanonicalField{"deviceId", t.DeviceID}, CanonicalField{"enrollmentId", t.EnrollmentID}, CanonicalField{"transitionId", t.TransitionID},
		CanonicalField{"oldBindingId", t.OldBindingID}, CanonicalField{"newBindingId", t.NewBindingID},
		CanonicalField{"oldProfile", t.OldProfile}, CanonicalField{"newProfile", t.NewProfile},
		CanonicalField{"oldPublicIdentityRef", t.OldPublicIdentityRef}, CanonicalField{"newPublicIdentityRef", t.NewPublicIdentityRef},
		CanonicalField{"oldGeneration", strconv.FormatUint(t.OldGeneration, 10)}, CanonicalField{"newGeneration", strconv.FormatUint(t.NewGeneration, 10)},
		CanonicalField{"oldBacking", t.OldBacking}, CanonicalField{"newBacking", t.NewBacking}, CanonicalField{"nonce", t.Nonce},
		CanonicalField{"issuedAt", t.IssuedAt}, CanonicalField{"expiresAt", t.ExpiresAt})
}
func rotationTimestamp(value string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || t.UTC().Format("2006-01-02T15:04:05.000Z") != value {
		return time.Time{}, fmt.Errorf("invalid rotation time")
	}
	return t, nil
}
func (t RotationTranscript) validate(state State, old, candidate Identity, transition string, now time.Time, allowExpired bool) error {
	origin, err := CanonicalInstanceURL(state.InstanceURL)
	if err != nil || origin != state.InstanceURL || t.Version != 1 || t.Audience != origin || t.DeviceID != state.DeviceID || t.EnrollmentID != state.EnrollmentID || t.TransitionID != transition || t.OldBindingID != state.IdentityBindingID || t.NewBindingID == "" || len(t.NewBindingID) > 128 || t.NewBindingID == t.OldBindingID || t.OldProfile != old.Profile() || t.NewProfile != P256IdentityProfile || t.OldPublicIdentityRef != old.PublicIdentityRef || t.NewPublicIdentityRef != candidate.PublicIdentityRef || t.OldGeneration != old.Generation || t.NewGeneration != candidate.Generation || t.NewGeneration != t.OldGeneration+1 || t.NewBacking != candidate.Backing || (t.OldBacking != "unknown" && t.OldBacking != old.Backing) {
		return fmt.Errorf("rotation transcript does not match local authority")
	}
	if _, err := decodeRaw(t.Nonce, 32); err != nil {
		return err
	}
	if _, err := decodeRaw(t.TransitionID, 32); err != nil {
		return err
	}
	issued, e1 := rotationTimestamp(t.IssuedAt)
	expires, e2 := rotationTimestamp(t.ExpiresAt)
	if e1 != nil || e2 != nil || expires.Sub(issued) != 5*time.Minute || issued.After(now.Add(time.Minute)) || !allowExpired && !now.Before(expires) {
		return fmt.Errorf("rotation challenge expired or invalid")
	}
	return nil
}
func (r RotationResult) validate(t RotationTranscript) error {
	committed, e1 := rotationTimestamp(r.CommittedAt)
	deadline, e2 := rotationTimestamp(r.OverlapExpiresAt)
	if e1 != nil || e2 != nil || deadline.Sub(committed) != 5*time.Minute || r.TransitionID != t.TransitionID || r.EnrollmentID != t.EnrollmentID || r.DeviceID != t.DeviceID || r.OldBindingID != t.OldBindingID || r.NewBindingID != t.NewBindingID || r.NewPublicIdentityRef != t.NewPublicIdentityRef || r.NewGeneration != t.NewGeneration || r.NewBacking != t.NewBacking {
		return fmt.Errorf("rotation result does not match prepared transition")
	}
	issued, _ := rotationTimestamp(t.IssuedAt)
	expires, _ := rotationTimestamp(t.ExpiresAt)
	if committed.Before(issued) || !committed.Before(expires) {
		return fmt.Errorf("rotation result outside original challenge")
	}
	return nil
}
