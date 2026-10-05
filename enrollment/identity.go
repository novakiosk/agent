package enrollment

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/novakiosk/agent/tpmsigner"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const identityFilename = "identity.json"

type Identity struct {
	signer            crypto.Signer
	tpmBundle         *tpmsigner.Bundle
	Backing           string
	Generation        uint64
	PublicIdentityRef string
	DeviceID          string
}

type persistedIdentity struct {
	Version           int               `json:"version"`
	Profile           string            `json:"profile"`
	PublicIdentityRef string            `json:"publicIdentityRef"`
	PrivateKey        string            `json:"privateKey,omitempty"`
	DeviceID          string            `json:"deviceId,omitempty"`
	Backing           string            `json:"backing,omitempty"`
	TPM               *tpmsigner.Bundle `json:"tpm,omitempty"`
	Generation        uint64            `json:"generation,omitempty"`
}

func IdentityPath(stateDir string) string { return filepath.Join(stateDir, identityFilename) }

func encodeRaw(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func decodeRaw(value string, size int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") || len(value) > size*2 {
		return nil, fmt.Errorf("invalid base64url value")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || encodeRaw(decoded) != value {
		return nil, fmt.Errorf("invalid base64url value")
	}
	return decoded, nil
}

func PublicIdentityRef(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key")
	}
	return ProvisionalIdentityProfile + ":" + encodeRaw(publicKey), nil
}

// ValidateDeviceID accepts the bounded, opaque identifier used to correlate
// an attended device enrollment. It deliberately permits externally supplied
// legacy IDs while generated IDs use UUID v4 spelling.
func ValidateDeviceID(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return fmt.Errorf("device ID must be 1-128 characters")
	}
	for index, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == ':' || character == '-') ||
			(index == 0 && (character < '0' || (character > '9' && character < 'A') || (character > 'Z' && character < 'a') || character > 'z')) {
			return fmt.Errorf("device ID contains unsupported characters")
		}
	}
	return nil
}

func GenerateDeviceID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate device ID: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], bytes[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], bytes[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], bytes[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], bytes[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], bytes[10:16])
	return string(encoded), nil
}

func GenerateIdentity() (Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate provisional identity: %w", err)
	}
	ref, err := PublicIdentityRef(publicKey)
	if err != nil {
		return Identity{}, err
	}
	deviceID, err := GenerateDeviceID()
	if err != nil {
		return Identity{}, err
	}
	return Identity{signer: privateKey, PublicIdentityRef: ref, DeviceID: deviceID}, nil
}

var ErrIdentity = errors.New("identity requires attended recovery")

func LoadIdentity(stateDir string) (Identity, error) { return loadIdentity(stateDir, true) }

// InspectIdentity validates the durable bundle without opening a TPM or creating handles.
func InspectIdentity(stateDir string) (Identity, error) { return loadIdentity(stateDir, false) }
func loadIdentity(stateDir string, openSigner bool) (Identity, error) {
	data, err := readIdentityFile(stateDir)
	if errors.Is(err, fs.ErrNotExist) {
		return Identity{}, ErrUnconfigured
	}
	if err != nil {
		return Identity{}, fmt.Errorf("%w: read bundle: %v", ErrIdentity, err)
	}
	identity, err := decodeIdentityMode(data, openSigner)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	return identity, nil
}
func (identity Identity) Close() error {
	if closer, ok := identity.signer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type publicOnlySigner struct{ public crypto.PublicKey }

func (signer publicOnlySigner) Public() crypto.PublicKey { return signer.public }
func (signer publicOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, ErrIdentity
}

func decodeIdentity(data []byte) (Identity, error) { return decodeIdentityMode(data, true) }
func decodeIdentityMode(data []byte, openSigner bool) (Identity, error) {
	var persisted persistedIdentity
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&persisted) != nil || decoder.Decode(new(any)) != io.EOF || persisted.Version != ProtocolVersion || !supportedIdentityProfile(persisted.Profile) {
		return Identity{}, fmt.Errorf("read agent identity: malformed identity")
	}
	if err := ValidateDeviceID(persisted.DeviceID); err != nil {
		return Identity{}, fmt.Errorf("identity requires explicit attended device ID migration: %w", err)
	}
	var signer crypto.Signer
	switch persisted.Profile {
	case ProvisionalIdentityProfile:
		if persisted.Backing != "" || persisted.Generation != 0 || persisted.TPM != nil {
			return Identity{}, fmt.Errorf("invalid legacy identity metadata")
		}
		key, err := decodeRaw(persisted.PrivateKey, ed25519.PrivateKeySize)
		if err != nil {
			return Identity{}, fmt.Errorf("invalid private material")
		}
		// Ed25519 private encoding includes the public suffix; validate it against the seed.
		derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !bytes.Equal(derived, key) {
			return Identity{}, fmt.Errorf("inconsistent Ed25519 private material")
		}
		signer = derived
	case P256IdentityProfile:
		if persisted.Generation < 1 || persisted.Generation > 9007199254740991 {
			return Identity{}, fmt.Errorf("invalid key generation")
		}
		switch persisted.Backing {
		case SoftwareP256:
			if persisted.TPM != nil {
				return Identity{}, fmt.Errorf("mixed identity backing")
			}
			der, err := base64.RawURLEncoding.Strict().DecodeString(persisted.PrivateKey)
			if err != nil || len(der) > 256 || encodeRaw(der) != persisted.PrivateKey {
				return Identity{}, fmt.Errorf("invalid private material")
			}
			key, err := x509.ParseECPrivateKey(der)
			if err != nil || key.Curve != elliptic.P256() {
				return Identity{}, fmt.Errorf("invalid P-256 private material")
			}
			signer = key
		case TPMP256:
			if persisted.PrivateKey != "" || persisted.TPM == nil {
				return Identity{}, fmt.Errorf("invalid TPM identity bundle")
			}
			public, err := tpmsigner.ValidateBundle(*persisted.TPM)
			if err != nil {
				return Identity{}, err
			}
			signer = publicOnlySigner{public: public}
		default:
			return Identity{}, fmt.Errorf("unsupported backing; TPM fallback forbidden")
		}
	}
	identity := Identity{signer: signer, tpmBundle: persisted.TPM, PublicIdentityRef: persisted.PublicIdentityRef, DeviceID: persisted.DeviceID, Backing: persisted.Backing, Generation: persisted.Generation}
	ref, err := signerPublicRef(signer)
	if err != nil || ref != persisted.PublicIdentityRef {
		return Identity{}, fmt.Errorf("read agent identity: public key mismatch")
	}
	if persisted.Backing == TPMP256 && openSigner {
		loaded, err := tpmsigner.Load(*persisted.TPM)
		if err != nil {
			return Identity{}, fmt.Errorf("TPM load failed; fix device permissions or hardware before retry: %w", err)
		}
		identity.signer = loaded
	}
	return identity, nil
}

// MigrateLegacyIdentity is an attended compatibility operation, never a load side effect.
func MigrateLegacyIdentity(stateDir, expectedDeviceID string) (Identity, error) {
	data, err := readIdentityFile(stateDir)
	if err != nil {
		return Identity{}, err
	}
	var persisted persistedIdentity
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&persisted) != nil || decoder.Decode(new(any)) != io.EOF || persisted.DeviceID != "" || persisted.Profile != ProvisionalIdentityProfile {
		return Identity{}, fmt.Errorf("not a legacy identity")
	}
	deviceID, err := migrateDeviceID(stateDir, persisted.PublicIdentityRef)
	if err != nil {
		return Identity{}, err
	}
	if expectedDeviceID != "" && expectedDeviceID != deviceID {
		return Identity{}, fmt.Errorf("legacy device ID does not match expected ID")
	}
	persisted.DeviceID = deviceID
	updated, err := json.Marshal(persisted)
	if err != nil {
		return Identity{}, err
	}
	identity, err := decodeIdentity(updated)
	if err != nil {
		return Identity{}, err
	}
	if err := SaveIdentityAtomic(stateDir, identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func migrateDeviceID(stateDir, expectedPublicIdentityRef string) (string, error) {
	state, stateErr := LoadState(stateDir)
	attempt, attemptErr := LoadAttempt(stateDir)
	if stateErr != nil && !errors.Is(stateErr, ErrUnconfigured) {
		return "", fmt.Errorf("read existing agent state during identity migration: %w", stateErr)
	}
	if attemptErr != nil && !errors.Is(attemptErr, ErrUnconfigured) {
		return "", fmt.Errorf("read existing pending attempt during identity migration: %w", attemptErr)
	}
	if stateErr == nil {
		if state.PublicIdentityRef == "" || state.PublicIdentityRef != expectedPublicIdentityRef {
			return "", fmt.Errorf("existing agent state identity does not match local identity")
		}
		return state.DeviceID, nil
	}
	if attemptErr == nil {
		if attempt.PublicIdentityRef != expectedPublicIdentityRef {
			return "", fmt.Errorf("existing pending attempt identity does not match local identity")
		}
		if attempt.Proof.Kind != ProvisionalIdentityProfile {
			return "", fmt.Errorf("existing pending attempt is not a provisional identity enrollment")
		}
		return attempt.DeviceID, nil
	}
	return "", fmt.Errorf("legacy identity requires matching authority state")
}

func SaveIdentityAtomic(stateDir string, identity Identity) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	ref, err := signerPublicRef(identity.signer)
	if err != nil || ref != identity.PublicIdentityRef {
		return fmt.Errorf("refusing to persist mismatched identity")
	}
	if err := ValidateDeviceID(identity.DeviceID); err != nil {
		return fmt.Errorf("refusing to persist invalid device ID: %w", err)
	}
	if identity.Profile() != ProvisionalIdentityProfile {
		return fmt.Errorf("P-256 identity creation requires CreateSoftwareIdentity")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedIdentity{
		Version: ProtocolVersion, Profile: identity.Profile(), PublicIdentityRef: identity.PublicIdentityRef,
		PrivateKey: encodeRaw(identity.signer.(ed25519.PrivateKey)), DeviceID: identity.DeviceID,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent identity")
	}
	return saveIdentityAtomic(stateDir, IdentityPath(stateDir), data)
}

func LoadOrCreateIdentity(stateDir string) (Identity, error) {
	identity, err := LoadIdentity(stateDir)
	if err == nil {
		return identity, nil
	}
	if !errors.Is(err, ErrUnconfigured) {
		return Identity{}, err
	}
	created := false
	if err := os.Mkdir(stateDir, 0700); err == nil {
		created = true
	} else if !errors.Is(err, fs.ErrExist) {
		return Identity{}, err
	}
	if !created {
		entries, err := os.ReadDir(stateDir)
		if err != nil {
			return Identity{}, err
		}
		if len(entries) != 1 || entries[0].Name() != ".authority.lock" {
			return Identity{}, fmt.Errorf("existing state directory has no identity; attended recovery required")
		}
	}
	directory, err := identityDirectory(stateDir)
	if err != nil {
		return Identity{}, err
	}
	defer directory.Close()
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX); err != nil {
		return Identity{}, err
	}
	defer syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	if err := emptyIdentityDirectory(directory); err != nil {
		return Identity{}, err
	}
	identity, err = GenerateIdentity()
	if err != nil {
		return Identity{}, err
	}
	data, err := json.Marshal(persistedIdentity{Version: ProtocolVersion, Profile: ProvisionalIdentityProfile, PublicIdentityRef: identity.PublicIdentityRef, PrivateKey: encodeRaw(identity.signer.(ed25519.PrivateKey)), DeviceID: identity.DeviceID})
	if err != nil {
		return Identity{}, err
	}
	if err := writeIdentityAt(directory, data); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func saveIdentityAtomic(stateDir, destination string, data []byte) error {
	if destination != IdentityPath(stateDir) {
		return fmt.Errorf("invalid identity destination")
	}
	return writeIdentityFile(stateDir, data)
}

func SignEnrollment(identity Identity, request Request) (string, error) {
	if request.PublicIdentityRef != identity.PublicIdentityRef || request.DeviceID != identity.DeviceID {
		return "", fmt.Errorf("request identity does not match local identity")
	}
	canonical := EnrollmentCanonical(request)
	if len(canonical) == 0 {
		return "", fmt.Errorf("canonical enrollment payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

func SignClaim(identity Identity, claim IdentityClaim) (string, error) {
	if claim.PublicIdentityRef != identity.PublicIdentityRef || claim.DeviceID != identity.DeviceID {
		return "", fmt.Errorf("claim identity does not match local identity")
	}
	canonical := ClaimCanonical(claim)
	if len(canonical) == 0 {
		return "", fmt.Errorf("canonical claim payload is too large")
	}
	return encodeIdentitySignature(identity, canonical)
}

const P256IdentityProfile = "nova-p256-sha256-v1"
const SoftwareP256 = "software-p256"
const TPMP256 = "tpm-p256"

func supportedIdentityProfile(profile string) bool {
	return profile == ProvisionalIdentityProfile || profile == P256IdentityProfile
}
func identityProfile(ref string) string   { profile, _, _ := strings.Cut(ref, ":"); return profile }
func (identity Identity) Profile() string { return identityProfile(identity.PublicIdentityRef) }
func signerPublicRef(signer crypto.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("missing identity signer")
	}
	switch key := signer.Public().(type) {
	case ed25519.PublicKey:
		return PublicIdentityRef(key)
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() && key.Curve.IsOnCurve(key.X, key.Y) {
			return P256IdentityProfile + ":" + encodeRaw(elliptic.Marshal(key.Curve, key.X, key.Y)), nil
		}
	}
	return "", fmt.Errorf("unsupported identity signer")
}

// CreateSoftwareIdentity explicitly provisions a new or pre-provisioned empty
// private directory. Existing identity or interrupted state is never repaired.
func CreateSoftwareIdentity(stateDir, deviceID string) (Identity, error) {
	return CreateP256Identity(stateDir, deviceID, SoftwareP256)
}
func CreateP256Identity(stateDir, deviceID, backing string) (Identity, error) {
	if err := ValidateDeviceID(deviceID); err != nil {
		return Identity{}, err
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return Identity{}, err
	}
	directory, err := identityDirectory(stateDir)
	if err != nil {
		return Identity{}, err
	}
	defer directory.Close()
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX); err != nil {
		return Identity{}, err
	}
	defer syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	if err := emptyIdentityDirectory(directory); err != nil {
		return Identity{}, err
	}
	identity, data, err := newP256Identity(deviceID, backing, 1)
	if err != nil {
		return Identity{}, err
	}
	keep := false
	defer func() {
		if !keep {
			identity.Close()
		}
	}()
	if err := writeIdentityAt(directory, data); err != nil {
		return Identity{}, err
	}
	parent, err := os.Open(filepath.Dir(stateDir))
	if err != nil {
		return Identity{}, err
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return Identity{}, err
	}
	keep = true
	return identity, nil
}

func (identity Identity) sign(canonical []byte) (string, error) {
	if len(canonical) == 0 || len(canonical) > MaxCanonicalBytes {
		return "", fmt.Errorf("invalid canonical payload size")
	}
	ref, err := signerPublicRef(identity.signer)
	if err != nil || ref != identity.PublicIdentityRef {
		return "", fmt.Errorf("%w: invalid signer", ErrIdentity)
	}
	var message = canonical
	var options crypto.SignerOpts = crypto.Hash(0)
	if identity.Profile() == P256IdentityProfile {
		digest := sha256.Sum256(canonical)
		message = digest[:]
		options = crypto.SHA256
	}
	signature, err := identity.signer.Sign(rand.Reader, message, options)
	if err != nil {
		return "", fmt.Errorf("%w: signing failed: %v", ErrIdentity, err)
	}
	return encodeRaw(signature), nil
}

func newP256Identity(deviceID, backing string, generation uint64) (Identity, []byte, error) {
	if ValidateDeviceID(deviceID) != nil || generation < 1 || generation > 9007199254740991 {
		return Identity{}, nil, fmt.Errorf("invalid candidate identity")
	}
	var signer crypto.Signer
	var bundle *tpmsigner.Bundle
	switch backing {
	case SoftwareP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Identity{}, nil, err
		}
		signer = key
	case TPMP256:
		key, value, err := tpmsigner.Create()
		if err != nil {
			return Identity{}, nil, fmt.Errorf("%w: TPM creation failed; select software explicitly only if intended: %v", ErrIdentity, err)
		}
		signer = key
		bundle = &value
	default:
		return Identity{}, nil, fmt.Errorf("unsupported identity backing")
	}
	ref, err := signerPublicRef(signer)
	if err != nil {
		if c, ok := signer.(io.Closer); ok {
			c.Close()
		}
		return Identity{}, nil, err
	}
	identity := Identity{signer: signer, tpmBundle: bundle, DeviceID: deviceID, PublicIdentityRef: ref, Backing: backing, Generation: generation}
	data, err := marshalIdentity(identity)
	if err != nil {
		identity.Close()
		return Identity{}, nil, err
	}
	return identity, data, nil
}
func marshalIdentity(identity Identity) ([]byte, error) {
	record := persistedIdentity{Version: ProtocolVersion, Profile: identity.Profile(), PublicIdentityRef: identity.PublicIdentityRef, DeviceID: identity.DeviceID, Backing: identity.Backing, Generation: identity.Generation, TPM: identity.tpmBundle}
	switch key := identity.signer.(type) {
	case ed25519.PrivateKey:
		record.PrivateKey = encodeRaw(key)
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		record.PrivateKey = encodeRaw(der)
	default:
		if identity.Backing != TPMP256 || identity.tpmBundle == nil {
			return nil, ErrIdentity
		}
	}
	return json.Marshal(record)
}

// SelectFreshBacking never substitutes software for a present but inaccessible
// TPM. Stored identities bypass selection entirely.
func SelectFreshBacking(selection string) (string, error) {
	switch selection {
	case "software":
		return SoftwareP256, nil
	case "tpm":
		return TPMP256, nil
	case "auto":
		if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			return TPMP256, nil
		} else if errors.Is(err, os.ErrNotExist) {
			return SoftwareP256, nil
		} else {
			return "", fmt.Errorf("%w: inspect TPM device: %v", ErrIdentity, err)
		}
	default:
		return "", fmt.Errorf("identity-backing must be auto, tpm, or software")
	}
}
