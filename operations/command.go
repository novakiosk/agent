package operations

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	CommandVersion           = 1
	CommandMessageType       = "operation.command"
	MaxCommandJSONBytes      = 2 * 1024
	MaxCommandCanonicalBytes = 2 * 1024
	MaxCommandLifetime       = time.Hour
	CommandClockSkew         = 2 * time.Minute
)

// Command is the complete v1 operation request. Its exact JSON fields are
// deliberately closed: there is no argv, unit, path, shell, or backend.
type Command struct {
	Version     int         `json:"version"`
	Type        string      `json:"type"`
	CommandID   string      `json:"commandId"`
	CommandType CommandType `json:"commandType"`
	IssuedAt    string      `json:"issuedAt"`
	ExpiresAt   string      `json:"expiresAt"`
	PayloadHash string      `json:"payloadHash"`
}

// SameCommand compares every closed v1 command field.  CommandID alone is
// not sufficient for replay: a reused ID with changed timestamps, type, or
// hash must remain a conflict rather than entering the durable replay path.
func SameCommand(left, right Command) bool {
	return left == right
}

// UnmarshalJSON rejects unknown fields so journal and protocol decoders do
// not silently widen the command contract.
func (command *Command) UnmarshalJSON(data []byte) error {
	type plain Command
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded plain
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("operations: malformed operation command")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("operations: malformed operation command")
	}
	*command = Command(decoded)
	return nil
}

func (command Command) Validate(now time.Time) error {
	return command.validate(now, false)
}

// ValidateForReplay retains all shape, hash, lifetime, and future-clock
// checks while allowing an already journaled accepted command to be replayed
// after its delivery window. It is never used for first acceptance or
// execution of a new command.
func (command Command) ValidateForReplay(now time.Time) error {
	return command.validate(now, true)
}

func (command Command) validate(now time.Time, allowExpired bool) error {
	if command.Version != CommandVersion || command.Type != CommandMessageType {
		return errors.New("operations: unsupported operation command")
	}
	if !validCommandID(command.CommandID) {
		return errors.New("operations: invalid commandId")
	}
	if !validCommandType(command.CommandType) {
		return errors.New("operations: invalid commandType")
	}
	issued, expires, err := command.canonicalTimes()
	if err != nil {
		return err
	}
	if expires.Before(issued) || expires.Equal(issued) || expires.Sub(issued) > MaxCommandLifetime {
		return errors.New("operations: invalid command lifetime")
	}
	if now.IsZero() {
		return errors.New("operations: invalid validation clock")
	}
	if issued.After(now.Add(CommandClockSkew)) {
		return errors.New("operations: command issued in the future")
	}
	if !allowExpired && !expires.After(now) {
		return errors.New("operations: command expired")
	}
	if !validPayloadHash(command.PayloadHash) {
		return errors.New("operations: invalid payloadHash")
	}
	expected, err := command.CanonicalPayloadHash()
	if err != nil || expected != command.PayloadHash {
		return errors.New("operations: payloadHash mismatch")
	}
	encoded, err := json.Marshal(command)
	if err != nil || len(encoded) > MaxCommandJSONBytes {
		return errors.New("operations: command exceeds JSON bound")
	}
	return nil
}

func (command Command) canonicalTimes() (time.Time, time.Time, error) {
	issued, err := parseCanonicalUTCTimestamp(command.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("operations: issuedAt: %w", err)
	}
	expires, err := parseCanonicalUTCTimestamp(command.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("operations: expiresAt: %w", err)
	}
	return issued, expires, nil
}

func parseCanonicalUTCTimestamp(value string) (time.Time, error) {
	if value == "" || len(value) > 64 || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 timestamp")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.Location() != time.UTC || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 timestamp")
	}
	return parsed, nil
}

func validCommandID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !isLowerHex(character) {
			return false
		}
	}
	return true
}

func isLowerHex(value rune) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
}

func validPayloadHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !isLowerHex(character) {
			return false
		}
	}
	return true
}

// CanonicalPayload excludes PayloadHash and is language-neutral. Base64url
// values keep field framing unambiguous across Go, TypeScript, and future
// implementations.
func (command Command) CanonicalPayload() ([]byte, error) {
	if command.Version != CommandVersion || command.Type != CommandMessageType || !validCommandID(command.CommandID) || !validCommandType(command.CommandType) {
		return nil, errors.New("operations: invalid operation command fields")
	}
	issued, expires, err := command.canonicalTimes()
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("operation-command-canonical-v1\n")
	writeCommandField(&builder, "version", "1")
	writeCommandField(&builder, "type", command.Type)
	writeCommandField(&builder, "commandId", command.CommandID)
	writeCommandField(&builder, "commandType", string(command.CommandType))
	writeCommandField(&builder, "issuedAt", issued.UTC().Format(time.RFC3339Nano))
	writeCommandField(&builder, "expiresAt", expires.UTC().Format(time.RFC3339Nano))
	canonical := []byte(builder.String())
	if len(canonical) > MaxCommandCanonicalBytes {
		return nil, errors.New("operations: canonical command exceeds bound")
	}
	return canonical, nil
}

func writeCommandField(builder *strings.Builder, name, value string) {
	builder.WriteString(name)
	builder.WriteByte('=')
	builder.WriteString(base64.RawURLEncoding.EncodeToString([]byte(value)))
	builder.WriteByte('\n')
}

func (command Command) CanonicalPayloadHash() (string, error) {
	payload, err := command.CanonicalPayload()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
