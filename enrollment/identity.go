package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const identityFilename = "identity.json"

type Identity struct {
	PrivateKey        ed25519.PrivateKey
	PublicIdentityRef string
	DeviceID          string
}

type persistedIdentity struct {
	Version           int    `json:"version"`
	Profile           string `json:"profile"`
	PublicIdentityRef string `json:"publicIdentityRef"`
	PrivateKey        string `json:"privateKey"`
	DeviceID          string `json:"deviceId,omitempty"`
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
	return Identity{PrivateKey: privateKey, PublicIdentityRef: ref, DeviceID: deviceID}, nil
}

func LoadIdentity(stateDir string) (Identity, error) {
	if strings.TrimSpace(stateDir) == "" {
		return Identity{}, fmt.Errorf("state directory is required")
	}
	data, err := readSecureFile(IdentityPath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return Identity{}, ErrUnconfigured
	}
	if err != nil {
		return Identity{}, fmt.Errorf("read agent identity: %w", err)
	}
	var persisted persistedIdentity
	if err := json.Unmarshal(data, &persisted); err != nil || persisted.Version != ProtocolVersion || persisted.Profile != ProvisionalIdentityProfile {
		return Identity{}, fmt.Errorf("read agent identity: malformed identity")
	}
	privateKeyBytes, err := decodeRaw(persisted.PrivateKey, ed25519.PrivateKeySize)
	if err != nil {
		return Identity{}, fmt.Errorf("read agent identity: invalid private material")
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	ref, err := PublicIdentityRef(privateKey.Public().(ed25519.PublicKey))
	if err != nil || ref != persisted.PublicIdentityRef {
		return Identity{}, fmt.Errorf("read agent identity: public key mismatch")
	}
	deviceID := persisted.DeviceID
	if deviceID == "" {
		deviceID, err = migrateDeviceID(stateDir, ref)
		if err != nil {
			return Identity{}, err
		}
		identity := Identity{PrivateKey: privateKey, PublicIdentityRef: ref, DeviceID: deviceID}
		if err := SaveIdentityAtomic(stateDir, identity); err != nil {
			return Identity{}, fmt.Errorf("migrate agent identity: %w", err)
		}
		return identity, nil
	}
	if err := ValidateDeviceID(deviceID); err != nil {
		return Identity{}, fmt.Errorf("read agent identity: invalid device ID: %w", err)
	}
	return Identity{PrivateKey: privateKey, PublicIdentityRef: ref, DeviceID: deviceID}, nil
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
	return GenerateDeviceID()
}

func SaveIdentityAtomic(stateDir string, identity Identity) error {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("refusing to persist invalid private material")
	}
	ref, err := PublicIdentityRef(identity.PrivateKey.Public().(ed25519.PublicKey))
	if err != nil || ref != identity.PublicIdentityRef {
		return fmt.Errorf("refusing to persist mismatched identity")
	}
	if err := ValidateDeviceID(identity.DeviceID); err != nil {
		return fmt.Errorf("refusing to persist invalid device ID: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}
	data, err := json.MarshalIndent(persistedIdentity{
		Version: ProtocolVersion, Profile: ProvisionalIdentityProfile,
		PublicIdentityRef: identity.PublicIdentityRef, PrivateKey: encodeRaw(identity.PrivateKey), DeviceID: identity.DeviceID,
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
	identity, err = GenerateIdentity()
	if err != nil {
		return Identity{}, err
	}
	if err := SaveIdentityAtomic(stateDir, identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func saveIdentityAtomic(stateDir, destination string, data []byte) error {
	temporary, err := os.CreateTemp(stateDir, ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create identity temporary: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect identity temporary: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close identity: %w", err)
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("commit identity: %w", err)
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return os.Chmod(destination, 0o600)
}

func SignEnrollment(identity Identity, request Request) (string, error) {
	if request.PublicIdentityRef != identity.PublicIdentityRef {
		return "", fmt.Errorf("request identity does not match local identity")
	}
	canonical := EnrollmentCanonical(request)
	if len(canonical) == 0 {
		return "", fmt.Errorf("canonical enrollment payload is too large")
	}
	return encodeRaw(ed25519.Sign(identity.PrivateKey, canonical)), nil
}

func SignClaim(identity Identity, claim IdentityClaim) (string, error) {
	if claim.PublicIdentityRef != identity.PublicIdentityRef {
		return "", fmt.Errorf("claim identity does not match local identity")
	}
	canonical := ClaimCanonical(claim)
	if len(canonical) == 0 {
		return "", fmt.Errorf("canonical claim payload is too large")
	}
	return encodeRaw(ed25519.Sign(identity.PrivateKey, canonical)), nil
}
