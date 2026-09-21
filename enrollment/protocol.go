package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/novakiosk/agent/operations"
)

const ProtocolVersion = 1
const ProvisionalIdentityProfile = "provisional-ed25519-v1"
const SessionPath = "/v1/device-sessions/v1"
const MaxMessageBytes = 1024 * 1024
const MaxCanonicalBytes = 16 * 1024
const IdleScreenCapability = "idle-screen-v4"
const RemoteDesktopCapability = "remote-desktop-v1"

// RemoteDesktopV2Capability is negotiated by rebuilt agents. The v1 desired
// and lifecycle ACK payloads remain unchanged; v2 adds a bounded fast poll
// exchange on the already-authenticated managed socket.
const RemoteDesktopV2Capability = "remote-desktop-v2"
const RemoteDesktopTunnelPath = "/v1/device-remote-desktop/v1/tunnel"
const RemoteDesktopPollInterval = time.Second

type DeviceKind string

const (
	DeviceKindKiosk       DeviceKind = "kiosk"
	DeviceKindPrintServer DeviceKind = "print-server"
)

func (kind DeviceKind) Valid() bool { return kind == DeviceKindKiosk || kind == DeviceKindPrintServer }

func EffectiveDeviceKind(kind DeviceKind) DeviceKind {
	if kind == "" {
		return DeviceKindKiosk
	}
	return kind
}

func ValidateDeviceKind(kind DeviceKind) error {
	if kind != "" && !kind.Valid() {
		return fmt.Errorf("device kind must be kiosk or print-server")
	}
	return nil
}

// ValidateScope bounds the operator-selected scope before it can enter the
// signed enrollment request. Scope ownership remains an exact server-side
// decision; the agent never derives or widens it from server responses.
func ValidateScope(scope string) error {
	if len(scope) == 0 || len(scope) > 256 {
		return fmt.Errorf("scope must be 1-256 characters")
	}
	for _, character := range scope {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == ':' || character == '-' {
			continue
		}
		return fmt.Errorf("scope contains unsupported characters")
	}
	return nil
}

type Proof struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Inventory struct {
	Hostname     string   `json:"hostname"`
	OSVersion    string   `json:"osVersion"`
	AgentVersion string   `json:"agentVersion"`
	Capabilities []string `json:"capabilities"`
}

type Request struct {
	Version           int        `json:"version"`
	Type              string     `json:"type"`
	IdempotencyKey    string     `json:"idempotencyKey"`
	DeviceID          string     `json:"deviceId"`
	PublicIdentityRef string     `json:"publicIdentityRef"`
	Proof             Proof      `json:"proof"`
	Inventory         Inventory  `json:"inventory"`
	RequestedScope    string     `json:"requestedScope"`
	Nonce             string     `json:"nonce"`
	Audience          string     `json:"audience"`
	ExpiresAt         string     `json:"expiresAt"`
	DeviceKind        DeviceKind `json:"deviceKind,omitempty"`
}

type Result struct {
	Version         int    `json:"version"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	EnrollmentID    string `json:"enrollmentId"`
	DeviceID        string `json:"deviceId"`
	ComparisonValue string `json:"comparisonValue"`
	ExpiresAt       string `json:"expiresAt"`
}

type State struct {
	Version                             int                   `json:"version"`
	Status                              string                `json:"status"`
	InstanceURL                         string                `json:"instanceUrl"`
	EnrollmentID                        string                `json:"enrollmentId"`
	DeviceID                            string                `json:"deviceId"`
	ComparisonValue                     string                `json:"comparisonValue"`
	ExpiresAt                           string                `json:"expiresAt"`
	PublicIdentityRef                   string                `json:"publicIdentityRef,omitempty"`
	IdentityBindingID                   string                `json:"identityBindingId,omitempty"`
	SessionID                           string                `json:"sessionId,omitempty"`
	HeartbeatSequence                   uint64                `json:"heartbeatSequence,omitempty"`
	LastHeartbeatAt                     string                `json:"lastHeartbeatAt,omitempty"`
	AckSequence                         uint64                `json:"ackSequence,omitempty"`
	LastAckResult                       string                `json:"lastAckResult,omitempty"`
	LastAckAt                           string                `json:"lastAckAt,omitempty"`
	LastRevisionID                      string                `json:"lastRevisionId,omitempty"`
	LastRevision                        uint64                `json:"lastRevision,omitempty"`
	LastAppliedURL                      string                `json:"lastAppliedUrl,omitempty"`
	IdleAckSequence                     uint64                `json:"idleAckSequence,omitempty"`
	LastIdleScreenID                    string                `json:"lastIdleScreenId,omitempty"`
	LastIdleRevisionID                  string                `json:"lastIdleRevisionId,omitempty"`
	LastIdlePayloadHash                 string                `json:"lastIdlePayloadHash,omitempty"`
	LastIdleAckResult                   string                `json:"lastIdleAckResult,omitempty"`
	LastIdleAckError                    string                `json:"lastIdleAckError,omitempty"`
	LastIdleAckAt                       string                `json:"lastIdleAckAt,omitempty"`
	LastIdleAckAccepted                 bool                  `json:"lastIdleAckAccepted,omitempty"`
	LastIdleRemoved                     bool                  `json:"lastIdleRemoved,omitempty"`
	RuntimeAckSequence                  uint64                `json:"runtimeAckSequence,omitempty"`
	LastRuntimeArtifactRevision         string                `json:"lastRuntimeArtifactRevision,omitempty"`
	LastRuntimeArtifactHash             string                `json:"lastRuntimeArtifactHash,omitempty"`
	LastRuntimeAckResult                string                `json:"lastRuntimeAckResult,omitempty"`
	LastRuntimeAckAt                    string                `json:"lastRuntimeAckAt,omitempty"`
	LastRuntimeAckAccepted              bool                  `json:"lastRuntimeAckAccepted,omitempty"`
	PrinterReportSequence               uint64                `json:"printerReportSequence,omitempty"`
	LastPrinterReportHash               string                `json:"lastPrinterReportHash,omitempty"`
	LastPrinterReportAttemptAt          string                `json:"lastPrinterReportAttemptAt,omitempty"`
	LastPrinterReportAccepted           bool                  `json:"lastPrinterReportAccepted,omitempty"`
	PrinterStatisticsSequence           uint64                `json:"printerStatisticsSequence,omitempty"`
	LastPrinterStatisticsHash           string                `json:"lastPrinterStatisticsHash,omitempty"`
	LastPrinterStatisticsAttemptAt      string                `json:"lastPrinterStatisticsAttemptAt,omitempty"`
	LastPrinterStatisticsAccepted       bool                  `json:"lastPrinterStatisticsAccepted,omitempty"`
	PrinterJobsSequence                 uint64                `json:"printerJobsSequence,omitempty"`
	LastPrinterJobsHash                 string                `json:"lastPrinterJobsHash,omitempty"`
	LastPrinterJobsAttemptAt            string                `json:"lastPrinterJobsAttemptAt,omitempty"`
	LastPrinterJobsAccepted             bool                  `json:"lastPrinterJobsAccepted,omitempty"`
	PrinterJobCommandSequence           uint64                `json:"printerJobCommandSequence,omitempty"`
	LastPrinterJobCommandID             string                `json:"lastPrinterJobCommandId,omitempty"`
	LastPrinterJobCommandHash           string                `json:"lastPrinterJobCommandHash,omitempty"`
	LastPrinterJobCommandResult         string                `json:"lastPrinterJobCommandResult,omitempty"`
	LastPrinterJobCommandError          string                `json:"lastPrinterJobCommandError,omitempty"`
	LastPrinterJobCommandAt             string                `json:"lastPrinterJobCommandAt,omitempty"`
	LastPrinterJobCommandAccepted       bool                  `json:"lastPrinterJobCommandAccepted,omitempty"`
	PrinterQueueCommandSequence         uint64                `json:"printerQueueCommandSequence,omitempty"`
	LastPrinterQueueCommandID           string                `json:"lastPrinterQueueCommandId,omitempty"`
	LastPrinterQueueCommandHash         string                `json:"lastPrinterQueueCommandHash,omitempty"`
	LastPrinterQueueCommandResult       string                `json:"lastPrinterQueueCommandResult,omitempty"`
	LastPrinterQueueCommandError        string                `json:"lastPrinterQueueCommandError,omitempty"`
	LastPrinterQueueCommandAffectedJobs uint64                `json:"lastPrinterQueueCommandAffectedJobs,omitempty"`
	LastPrinterQueueCommandAt           string                `json:"lastPrinterQueueCommandAt,omitempty"`
	LastPrinterQueueCommandAccepted     bool                  `json:"lastPrinterQueueCommandAccepted,omitempty"`
	InventorySequence                   uint64                `json:"inventorySequence,omitempty"`
	LastInventoryHash                   string                `json:"lastInventoryHash,omitempty"`
	LastInventory                       *operations.Inventory `json:"lastInventory,omitempty"`
	InventoryPending                    bool                  `json:"inventoryPending,omitempty"`
	OperationSequence                   uint64                `json:"operationSequence,omitempty"`
	DeviceKind                          DeviceKind            `json:"deviceKind,omitempty"`
	PrinterQueuesApplyPending           *bool                 `json:"printerQueuesApplyPending,omitempty"`
	PrinterQueuesAppliedHash            string                `json:"printerQueuesAppliedHash,omitempty"`
	PrinterDesiredHash                  string                `json:"printerDesiredHash,omitempty"`
	PrinterAckSequence                  uint64                `json:"printerAckSequence,omitempty"`
	LastPrinterReconcileResult          string                `json:"lastPrinterReconcileResult,omitempty"`
	LastPrinterReconcileError           string                `json:"lastPrinterReconcileError,omitempty"`
	LastPrinterReconcileAt              string                `json:"lastPrinterReconcileAt,omitempty"`
	LastPrinterReconcileAccepted        bool                  `json:"lastPrinterReconcileAccepted,omitempty"`
	RemoteDesktopAckSequence            uint64                `json:"remoteDesktopAckSequence,omitempty"`
	LastRemoteDesktopSessionID          string                `json:"lastRemoteDesktopSessionId,omitempty"`
	LastRemoteDesktopAction             string                `json:"lastRemoteDesktopAction,omitempty"`
	LastRemoteDesktopResult             string                `json:"lastRemoteDesktopResult,omitempty"`
	LastRemoteDesktopError              string                `json:"lastRemoteDesktopError,omitempty"`
	LastRemoteDesktopAckAt              string                `json:"lastRemoteDesktopAckAt,omitempty"`
	BrowserCommandSequence              uint64                `json:"browserCommandSequence,omitempty"`
	LastBrowserCommandID                string                `json:"lastBrowserCommandId,omitempty"`
	LastBrowserCommandHash              string                `json:"lastBrowserCommandHash,omitempty"`
	LastBrowserCommandResult            string                `json:"lastBrowserCommandResult,omitempty"`
	LastBrowserCommandError             string                `json:"lastBrowserCommandError,omitempty"`
	LastBrowserCommandObservedURL       string                `json:"lastBrowserCommandObservedUrl,omitempty"`
	LastBrowserCommandZoom              *int                  `json:"lastBrowserCommandZoom,omitempty"`
	LastBrowserCommandAt                string                `json:"lastBrowserCommandAt,omitempty"`
	LastBrowserCommandAccepted          bool                  `json:"lastBrowserCommandAccepted,omitempty"`
}

type IdentityClaim struct {
	Version           int    `json:"version"`
	Type              string `json:"type"`
	EnrollmentID      string `json:"enrollmentId"`
	DeviceID          string `json:"deviceId"`
	PublicIdentityRef string `json:"publicIdentityRef"`
	Nonce             string `json:"nonce"`
	Audience          string `json:"audience"`
	ExpiresAt         string `json:"expiresAt"`
	Signature         string `json:"signature"`
}

type IdentityClaimResult struct {
	Version           int     `json:"version"`
	Type              string  `json:"type"`
	Status            string  `json:"status"`
	EnrollmentID      string  `json:"enrollmentId"`
	DeviceID          string  `json:"deviceId"`
	IdentityState     string  `json:"identityState"`
	IdentityBindingID *string `json:"identityBindingId"`
	SessionPath       *string `json:"sessionPath"`
}

type CanonicalField struct {
	Name  string
	Value string
}

func CanonicalV1(kind string, fields ...CanonicalField) []byte {
	var builder strings.Builder
	builder.WriteString("nova-canonical-v1\ntype=")
	builder.WriteString(base64.RawURLEncoding.EncodeToString([]byte(kind)))
	builder.WriteByte('\n')
	for _, field := range fields {
		builder.WriteString(field.Name)
		builder.WriteByte('=')
		builder.WriteString(base64.RawURLEncoding.EncodeToString([]byte(field.Value)))
		builder.WriteByte('\n')
	}
	value := []byte(builder.String())
	if len(value) > MaxCanonicalBytes {
		return nil
	}
	return value
}

func EnrollmentCanonical(request Request) []byte {
	return enrollmentCanonical(request, request.DeviceKind != "")
}

// enrollmentCanonical supports both the role-bound form and the original
// kiosk form. The latter is retained only for absent deviceKind values.
func enrollmentCanonical(request Request, includeKind bool) []byte {
	capabilities, _ := json.Marshal(request.Inventory.Capabilities)
	fields := []CanonicalField{
		{"version", "1"},
		{"profile", ProvisionalIdentityProfile},
		{"idempotencyKey", request.IdempotencyKey},
		{"deviceId", request.DeviceID},
	}
	if includeKind {
		fields = append(fields, CanonicalField{"deviceKind", string(EffectiveDeviceKind(request.DeviceKind))})
	}
	fields = append(fields,
		CanonicalField{"publicIdentityRef", request.PublicIdentityRef},
		CanonicalField{"requestedScope", request.RequestedScope},
		CanonicalField{"nonce", request.Nonce},
		CanonicalField{"audience", request.Audience},
		CanonicalField{"expiresAt", request.ExpiresAt},
		CanonicalField{"hostname", request.Inventory.Hostname},
		CanonicalField{"osVersion", request.Inventory.OSVersion},
		CanonicalField{"agentVersion", request.Inventory.AgentVersion},
		CanonicalField{"capabilities", string(capabilities)},
	)
	return CanonicalV1("bootstrap.enrollment", fields...)
}

func ClaimCanonical(claim IdentityClaim) []byte {
	return CanonicalV1("bootstrap.identity.claim",
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"enrollmentId", claim.EnrollmentID},
		CanonicalField{"deviceId", claim.DeviceID},
		CanonicalField{"publicIdentityRef", claim.PublicIdentityRef},
		CanonicalField{"nonce", claim.Nonce},
		CanonicalField{"audience", claim.Audience},
		CanonicalField{"expiresAt", claim.ExpiresAt},
	)
}

type ChallengeResponse struct {
	Version           int    `json:"version"`
	Type              string `json:"type"`
	Profile           string `json:"profile"`
	SessionID         string `json:"sessionId"`
	ChallengeID       string `json:"challengeId"`
	EnrollmentID      string `json:"enrollmentId"`
	IdentityBindingID string `json:"identityBindingId"`
	DeviceID          string `json:"deviceId"`
	PublicIdentityRef string `json:"publicIdentityRef"`
	Nonce             string `json:"nonce"`
	Audience          string `json:"audience"`
	ExpiresAt         string `json:"expiresAt"`
	Signature         string `json:"signature"`
}

func ChallengeCanonical(response ChallengeResponse) []byte {
	return CanonicalV1("session.challenge.response",
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", response.SessionID},
		CanonicalField{"challengeId", response.ChallengeID},
		CanonicalField{"enrollmentId", response.EnrollmentID},
		CanonicalField{"identityBindingId", response.IdentityBindingID},
		CanonicalField{"deviceId", response.DeviceID},
		CanonicalField{"publicIdentityRef", response.PublicIdentityRef},
		CanonicalField{"nonce", response.Nonce},
		CanonicalField{"audience", response.Audience},
		CanonicalField{"expiresAt", response.ExpiresAt},
	)
}

type Heartbeat struct {
	Version     int         `json:"version"`
	Type        string      `json:"type"`
	Profile     string      `json:"profile"`
	SessionID   string      `json:"sessionId"`
	DeviceID    string      `json:"deviceId"`
	Sequence    uint64      `json:"sequence"`
	ObservedAt  string      `json:"observedAt"`
	DisplayMode DisplayMode `json:"displayMode"`
	Signature   string      `json:"signature"`
}

func HeartbeatCanonical(heartbeat Heartbeat) []byte {
	fields := []CanonicalField{
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", heartbeat.SessionID},
		CanonicalField{"deviceId", heartbeat.DeviceID},
		CanonicalField{"sequence", fmt.Sprintf("%d", heartbeat.Sequence)},
		CanonicalField{"observedAt", heartbeat.ObservedAt},
	}
	// An empty mode is retained solely for the legacy signed heartbeat
	// identity fixture. New agents always set a valid mode, including
	// unknown, so their canonical payload is unambiguous.
	if heartbeat.DisplayMode != "" {
		fields = append(fields, CanonicalField{"displayMode", string(heartbeat.DisplayMode)})
	}
	return CanonicalV1("session.heartbeat", fields...)
}

// DesiredSnapshot carries the existing content desired state and an optional
// signed-session runtime artifact. A nil Desired value means no group exists.
type DesiredSnapshot struct {
	Version             int                      `json:"version"`
	Type                string                   `json:"type"`
	SessionID           string                   `json:"sessionId"`
	DeviceID            string                   `json:"deviceId"`
	Desired             *DesiredContent          `json:"desired"`
	Idle                *IdleDesired             `json:"idle"`
	Runtime             *RuntimeArtifact         `json:"runtime"`
	Operation           *operations.Command      `json:"operation"`
	RemoteDesktop       *RemoteDesktopDesired    `json:"remoteDesktop"`
	BrowserCommand      *BrowserCommand          `json:"browserCommand"`
	PrinterJobCommand   *PrinterJobCommand       `json:"printerJobCommand"`
	PrinterQueueCommand *PrinterQueueCommand     `json:"printerQueueCommand"`
	RemoteDesktopPoll   *RemoteDesktopPollPolicy `json:"remoteDesktopPoll,omitempty"`
}

// RemoteDesktopPollPolicy is sent only to agents which negotiated v2. It is
// deliberately small and exact: the agent never derives a poll endpoint or
// cadence from arbitrary desired state.
type RemoteDesktopPollPolicy struct {
	Enabled    bool `json:"enabled"`
	IntervalMs int  `json:"intervalMs"`
}

type RemoteDesktopPoll struct {
	Version    int    `json:"version"`
	Type       string `json:"type"`
	Profile    string `json:"profile"`
	SessionID  string `json:"sessionId"`
	DeviceID   string `json:"deviceId"`
	Sequence   uint64 `json:"sequence"`
	ObservedAt string `json:"observedAt"`
	Signature  string `json:"signature"`
}

type RemoteDesktopPollResult struct {
	Version       int                   `json:"version"`
	Type          string                `json:"type"`
	SessionID     string                `json:"sessionId"`
	DeviceID      string                `json:"deviceId"`
	Sequence      uint64                `json:"sequence"`
	Enabled       bool                  `json:"enabled"`
	RemoteDesktop *RemoteDesktopDesired `json:"remoteDesktop"`
}

// RemoteDesktopDesired has no arbitrary endpoint, command, or environment;
// the agent derives the control-plane tunnel from enrolled InstanceURL.
type RemoteDesktopDesired struct {
	Version        int    `json:"version"`
	Type           string `json:"type"`
	SessionID      string `json:"sessionId"`
	Action         string `json:"action"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
	TunnelPath     string `json:"tunnelPath"`
	DeviceToken    string `json:"deviceToken"`
	WayVNCUsername string `json:"wayvncUsername"`
	WayVNCPassword string `json:"wayvncPassword"`
}

func ValidateRemoteDesktopDesired(desired RemoteDesktopDesired, now time.Time) error {
	if desired.Version != ProtocolVersion || desired.Type != "remote-desktop.desired" || !validRemoteDesktopID(desired.SessionID) || (desired.Action != "start" && desired.Action != "stop") || desired.TunnelPath != RemoteDesktopTunnelPath {
		return fmt.Errorf("remote desktop desired identity is invalid")
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, desired.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, desired.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !canonicalRemoteDesktopTime(desired.IssuedAt, issued) || !canonicalRemoteDesktopTime(desired.ExpiresAt, expires) || issued.After(now.Add(5*time.Minute)) || !expires.After(issued) || expires.Sub(issued) > 30*time.Minute || (desired.Action == "start" && expires.Before(now.Add(-5*time.Minute))) {
		return fmt.Errorf("remote desktop desired timestamps are invalid")
	}
	for _, value := range []string{desired.DeviceToken, desired.WayVNCUsername, desired.WayVNCPassword} {
		if len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("remote desktop credential is invalid")
		}
	}
	if desired.Action == "start" {
		if !remoteDesktopToken(desired.DeviceToken) || !remoteDesktopUsername(desired.WayVNCUsername) || !remoteDesktopToken(desired.WayVNCPassword) {
			return fmt.Errorf("remote desktop start credentials are invalid")
		}
	} else if desired.DeviceToken != "" || desired.WayVNCUsername != "" || desired.WayVNCPassword != "" {
		return fmt.Errorf("remote desktop stop must not contain credentials")
	}
	return nil
}

func remoteDesktopToken(value string) bool {
	if len(value) < 20 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func remoteDesktopUsername(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validRemoteDesktopID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func canonicalRemoteDesktopTime(raw string, parsed time.Time) bool {
	if !strings.HasSuffix(raw, "Z") {
		return false
	}
	canonical := parsed.UTC().Format(time.RFC3339Nano)
	// JavaScript Date#toISOString uses exactly three fractional digits,
	// including .000; Go's RFC3339Nano formatter elides trailing zeroes.
	return raw == canonical || raw == parsed.UTC().Format("2006-01-02T15:04:05.000Z")
}

// IdleDesired is the bounded v4 static idle surface delivered alongside the
// authenticated desired snapshot. Its acknowledgement is a separate stream
// so idle runtime failures cannot mask content/browser evidence.
type IdleDesired struct {
	Type            string          `json:"type"`
	IdleScreenID    string          `json:"idleScreenId"`
	RevisionID      string          `json:"revisionId"`
	Revision        uint64          `json:"revision"`
	PayloadHash     string          `json:"payloadHash"`
	TimeoutSeconds  uint64          `json:"timeoutSeconds"`
	BackgroundColor string          `json:"backgroundColor"`
	Logos           []IdleLogo      `json:"logos"`
	VideoURL        *string         `json:"videoUrl"`
	CanvasAspect    string          `json:"canvasAspect"`
	Texts           []IdleTextBlock `json:"texts"`
}

type IdleTextBlock struct {
	ID              string `json:"id"`
	Text            string `json:"text"`
	Color           string `json:"color"`
	Font            string `json:"font"`
	FontSizePercent uint64 `json:"fontSizePercent"`
	FontWeight      string `json:"fontWeight"`
	TextAlign       string `json:"textAlign"`
	XPercent        uint64 `json:"xPercent"`
	YPercent        uint64 `json:"yPercent"`
}

type IdleLogo struct {
	ID           string `json:"id"`
	SHA256       string `json:"sha256"`
	MIME         string `json:"mime"`
	SizeBytes    uint64 `json:"sizeBytes"`
	DisplayName  string `json:"displayName"`
	Position     string `json:"position"`
	WidthPercent uint64 `json:"widthPercent"`
}

type DesiredContent struct {
	Type        string         `json:"type"`
	GroupID     string         `json:"groupId"`
	RevisionID  string         `json:"revisionId"`
	Revision    uint64         `json:"revision"`
	URL         string         `json:"url,omitempty"`
	PayloadHash string         `json:"payloadHash"`
	Items       []PlaylistItem `json:"items,omitempty"`
}

type PlaylistItem struct {
	Label           string `json:"label"`
	URL             string `json:"url"`
	DurationSeconds uint64 `json:"durationSeconds"`
}

type RuntimeArtifact struct {
	Version          int                       `json:"version"`
	Type             string                    `json:"type"`
	Status           string                    `json:"status"`
	ArtifactRevision string                    `json:"artifactRevision"`
	ArtifactHash     string                    `json:"artifactHash"`
	Sway             *RuntimeComponent         `json:"sway"`
	NOVAKeys         *RuntimeComponent         `json:"novaKeys"`
	Layouts          []RuntimeLayout           `json:"layouts"`
	BlockedReason    *string                   `json:"blockedReason"`
	Browser          *RuntimeBrowserManagement `json:"browser,omitempty"`
}

type RuntimeBrowserManagement struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	Kiosk         bool   `json:"kiosk"`
	KioskPrinting bool   `json:"kioskPrinting"`
}

type RuntimeComponent struct {
	Revision       uint64 `json:"revision"`
	SourceRevision uint64 `json:"sourceRevision"`
	Source         string `json:"source"`
	Mode           string `json:"mode"`
	Text           string `json:"text"`
}

type RuntimeLayout struct {
	LanguageCode string `json:"languageCode"`
	TOML         string `json:"toml"`
}

type RuntimeAck struct {
	Version          int     `json:"version"`
	Type             string  `json:"type"`
	Profile          string  `json:"profile"`
	SessionID        string  `json:"sessionId"`
	DeviceID         string  `json:"deviceId"`
	ArtifactRevision string  `json:"artifactRevision"`
	ArtifactHash     string  `json:"artifactHash"`
	Result           string  `json:"result"`
	ErrorCategory    *string `json:"errorCategory"`
	ObservedAt       string  `json:"observedAt"`
	Sequence         uint64  `json:"sequence"`
	Signature        string  `json:"signature"`
}

type DesiredAck struct {
	Version       int     `json:"version"`
	Type          string  `json:"type"`
	Profile       string  `json:"profile"`
	SessionID     string  `json:"sessionId"`
	DeviceID      string  `json:"deviceId"`
	GroupID       string  `json:"groupId"`
	RevisionID    string  `json:"revisionId"`
	Revision      uint64  `json:"revision"`
	Result        string  `json:"result"`
	ObservedURL   string  `json:"observedUrl"`
	ErrorCategory *string `json:"errorCategory"`
	ObservedAt    string  `json:"observedAt"`
	Sequence      uint64  `json:"sequence"`
	Signature     string  `json:"signature"`
}

type IdleAck struct {
	Version       int     `json:"version"`
	Type          string  `json:"type"`
	Profile       string  `json:"profile"`
	SessionID     string  `json:"sessionId"`
	DeviceID      string  `json:"deviceId"`
	IdleScreenID  string  `json:"idleScreenId"`
	RevisionID    string  `json:"revisionId"`
	PayloadHash   string  `json:"payloadHash"`
	Result        string  `json:"result"`
	ErrorCategory *string `json:"errorCategory"`
	ObservedAt    string  `json:"observedAt"`
	Sequence      uint64  `json:"sequence"`
	Signature     string  `json:"signature"`
}

type RemoteDesktopAck struct {
	Version         int     `json:"version"`
	Type            string  `json:"type"`
	Profile         string  `json:"profile"`
	SessionID       string  `json:"sessionId"`
	DeviceID        string  `json:"deviceId"`
	RemoteSessionID string  `json:"remoteSessionId"`
	Action          string  `json:"action"`
	Result          string  `json:"result"`
	ErrorCategory   *string `json:"errorCategory"`
	ObservedAt      string  `json:"observedAt"`
	Sequence        uint64  `json:"sequence"`
	Signature       string  `json:"signature"`
}

func DesiredAckCanonical(ack DesiredAck) []byte {
	errorCategory := ""
	if ack.ErrorCategory != nil {
		errorCategory = *ack.ErrorCategory
	}
	return CanonicalV1("desired.ack",
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", ack.SessionID},
		CanonicalField{"deviceId", ack.DeviceID},
		CanonicalField{"groupId", ack.GroupID},
		CanonicalField{"revisionId", ack.RevisionID},
		CanonicalField{"revision", fmt.Sprintf("%d", ack.Revision)},
		CanonicalField{"result", ack.Result},
		CanonicalField{"observedUrl", ack.ObservedURL},
		CanonicalField{"errorCategory", errorCategory},
		CanonicalField{"observedAt", ack.ObservedAt},
		CanonicalField{"sequence", fmt.Sprintf("%d", ack.Sequence)},
	)
}

func RuntimeAckCanonical(ack RuntimeAck) []byte {
	errorCategory := ""
	if ack.ErrorCategory != nil {
		errorCategory = *ack.ErrorCategory
	}
	return CanonicalV1("runtime.ack",
		CanonicalField{"version", "1"},
		CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", ack.SessionID},
		CanonicalField{"deviceId", ack.DeviceID},
		CanonicalField{"artifactRevision", ack.ArtifactRevision},
		CanonicalField{"artifactHash", ack.ArtifactHash},
		CanonicalField{"result", ack.Result},
		CanonicalField{"errorCategory", errorCategory},
		CanonicalField{"observedAt", ack.ObservedAt},
		CanonicalField{"sequence", fmt.Sprintf("%d", ack.Sequence)},
	)
}

func IdleAckCanonical(ack IdleAck) []byte {
	errorCategory := ""
	if ack.ErrorCategory != nil {
		errorCategory = *ack.ErrorCategory
	}
	return CanonicalV1("idle.desired.ack",
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", ack.SessionID}, CanonicalField{"deviceId", ack.DeviceID},
		CanonicalField{"idleScreenId", ack.IdleScreenID}, CanonicalField{"revisionId", ack.RevisionID},
		CanonicalField{"payloadHash", ack.PayloadHash}, CanonicalField{"result", ack.Result},
		CanonicalField{"errorCategory", errorCategory}, CanonicalField{"observedAt", ack.ObservedAt},
		CanonicalField{"sequence", fmt.Sprintf("%d", ack.Sequence)},
	)
}

func RemoteDesktopAckCanonical(ack RemoteDesktopAck) []byte {
	errorCategory := ""
	if ack.ErrorCategory != nil {
		errorCategory = *ack.ErrorCategory
	}
	return CanonicalV1("remote-desktop.ack",
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", ack.SessionID}, CanonicalField{"deviceId", ack.DeviceID},
		CanonicalField{"remoteSessionId", ack.RemoteSessionID}, CanonicalField{"action", ack.Action},
		CanonicalField{"result", ack.Result}, CanonicalField{"errorCategory", errorCategory},
		CanonicalField{"observedAt", ack.ObservedAt}, CanonicalField{"sequence", fmt.Sprintf("%d", ack.Sequence)},
	)
}

// RemoteDesktopPollCanonical is signed by the enrolled identity. The poll
// remains bound to both the managed session and device, and its sequence is
// monotonic for the lifetime of that WebSocket connection.
func RemoteDesktopPollCanonical(poll RemoteDesktopPoll) []byte {
	return CanonicalV1("remote-desktop.poll",
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", poll.SessionID}, CanonicalField{"deviceId", poll.DeviceID},
		CanonicalField{"sequence", fmt.Sprintf("%d", poll.Sequence)}, CanonicalField{"observedAt", poll.ObservedAt},
	)
}

func decodeStrictBounded(data []byte, destination any, maxBytes int) error {
	if len(data) > maxBytes {
		return fmt.Errorf("message is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("malformed protocol message")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("malformed protocol message")
	}
	return nil
}

func decodeStrict(data []byte, destination any) error {
	return decodeStrictBounded(data, destination, MaxCanonicalBytes)
}

func validateInstance(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("instance URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("instance URL must be an HTTPS origin without credentials, query, fragment, or path")
	}
	// Persist and sign the same origin spelling used by the control plane:
	// lower-case scheme/hostname, explicit non-default port, and no slash.
	hostname := strings.ToLower(parsed.Hostname())
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port := parsed.Port(); port != "" && port != "443" {
		hostname += ":" + port
	}
	parsed.Scheme = "https"
	parsed.Host = hostname
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.ForceQuery = false
	return parsed, nil
}

// CanonicalInstanceURL is the persisted/audience spelling shared by the CLI
// and control plane. It accepts an optional trailing slash but never returns
// one, and does not carry credentials, paths, queries, or fragments.
func CanonicalInstanceURL(raw string) (string, error) {
	parsed, err := validateInstance(raw)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// CanonicalPresentationURL applies the server's single-url-v1 URL spelling.
// Fragments are retained because they are part of the browser's top-level
// page URL, even though they are not sent in an HTTP request.
func CanonicalPresentationURL(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 2048 {
		return "", fmt.Errorf("presentation URL is out of bounds")
	}
	if strings.HasSuffix(raw, "#") {
		return "", fmt.Errorf("presentation URL fragment is invalid")
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] != '%' {
			continue
		}
		if index+2 >= len(raw) || !isHexByte(raw[index+1]) || !isHexByte(raw[index+2]) {
			return "", fmt.Errorf("presentation URL contains an invalid percent escape")
		}
		index += 2
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("presentation URL must be HTTPS without credentials")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("presentation URL host is required")
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port := parsed.Port(); port != "" && port != "443" {
		hostname += ":" + port
	}
	parsed.Scheme = "https"
	parsed.Host = hostname
	normalized := parsed.String()
	if len(normalized) > 2048 {
		return "", fmt.Errorf("presentation URL is too long")
	}
	return normalized, nil
}

func isHexByte(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
}

const (
	IdleDesiredType       = "idle-screen-v4"
	IdleMaxTextRunes      = 500
	IdleMaxTotalTextRunes = 2000
	IdleMaxTextBlocks     = 8
	IdleMinTimeoutSeconds = 5
	IdleMaxTimeoutSeconds = 86400
)

func IdleScreenPayloadCanonical(desired IdleDesired) []byte {
	logosList := make([]IdleLogo, len(desired.Logos))
	copy(logosList, desired.Logos)
	positions := map[string]int{"top-left": 0, "top-center": 1, "top-right": 2, "middle-left": 3, "middle-center": 4, "middle-right": 5, "bottom-left": 6, "bottom-center": 7, "bottom-right": 8}
	sort.Slice(logosList, func(i, j int) bool { return positions[logosList[i].Position] < positions[logosList[j].Position] })
	logos := canonicalIdleJSON(logosList)
	video := ""
	if desired.VideoURL != nil {
		video = *desired.VideoURL
	}
	textsList := desired.Texts
	if textsList == nil {
		textsList = []IdleTextBlock{}
	}
	texts := canonicalIdleJSON(textsList)
	return []byte("idle-screen-v4\n" +
		"timeoutSeconds=" + strconv.FormatUint(desired.TimeoutSeconds, 10) + "\n" +
		"backgroundColor=" + desired.BackgroundColor + "\n" +
		"logos=" + base64.RawURLEncoding.EncodeToString(logos) + "\n" +
		"videoUrl=" + base64.RawURLEncoding.EncodeToString([]byte(video)) + "\n" +
		"canvasAspect=" + desired.CanvasAspect + "\n" +
		"texts=" + base64.RawURLEncoding.EncodeToString(texts) + "\n")
}

func canonicalIdleJSON(value any) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
}

func IdleScreenPayloadHash(desired IdleDesired) string {
	digest := sha256.Sum256(IdleScreenPayloadCanonical(desired))
	return hex.EncodeToString(digest[:])
}

var (
	idleElementIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	idleVideoEmbedPattern = regexp.MustCompile(`^/embed/[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_-]{1,128}\?autoplay=true&loop=true&muted=true$`)
	idleVideoHostPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.b-cdn\.net$`)
)

func ValidateIdleDesired(desired IdleDesired) error {
	if desired.Type != IdleDesiredType || desired.IdleScreenID == "" || desired.RevisionID == "" || desired.Revision == 0 || len(desired.PayloadHash) != 64 || strings.Trim(desired.PayloadHash, "0123456789abcdef") != "" {
		return fmt.Errorf("idle desired identity is invalid")
	}
	if desired.Texts == nil {
		return fmt.Errorf("idle desired texts must be an array")
	}
	if desired.TimeoutSeconds < IdleMinTimeoutSeconds || desired.TimeoutSeconds > IdleMaxTimeoutSeconds || !regexpColor(desired.BackgroundColor) {
		return fmt.Errorf("idle desired fields are invalid")
	}
	if desired.CanvasAspect != "16:9" && desired.CanvasAspect != "9:16" {
		return fmt.Errorf("idle desired v4 fields are invalid")
	}
	if len(desired.Texts) > IdleMaxTextBlocks {
		return fmt.Errorf("idle desired texts are invalid")
	}
	ids := map[string]bool{}
	totalTextRunes := 0
	for _, text := range desired.Texts {
		if !idleElementIDPattern.MatchString(text.ID) || ids[text.ID] || len([]rune(text.Text)) < 1 || len([]rune(text.Text)) > IdleMaxTextRunes || strings.ContainsAny(text.Text, "<>") {
			return fmt.Errorf("idle desired text block is invalid")
		}
		for _, character := range text.Text {
			if character == 0x7f || (character < 0x20 && character != '\t' && character != '\n' && character != '\r') {
				return fmt.Errorf("idle desired text block contains a control character")
			}
		}
		totalTextRunes += len([]rune(text.Text))
		if totalTextRunes > IdleMaxTotalTextRunes || !regexpColor(text.Color) || !isIdleFontID(text.Font) || text.FontSizePercent < 2 || text.FontSizePercent > 20 || text.FontWeight != "normal" && text.FontWeight != "bold" || text.TextAlign != "left" && text.TextAlign != "center" && text.TextAlign != "right" || text.XPercent < 5 || text.XPercent > 95 || text.YPercent < 5 || text.YPercent > 95 {
			return fmt.Errorf("idle desired text block fields are invalid")
		}
		ids[text.ID] = true
	}
	if len(desired.Logos) > 8 {
		return fmt.Errorf("idle desired logos are invalid")
	}
	positions := map[string]bool{}
	allowedPositions := map[string]bool{"top-left": true, "top-center": true, "top-right": true, "middle-left": true, "middle-center": true, "middle-right": true, "bottom-left": true, "bottom-center": true, "bottom-right": true}
	for _, logo := range desired.Logos {
		if !idleElementIDPattern.MatchString(logo.ID) || len(logo.SHA256) != 64 || strings.Trim(logo.SHA256, "0123456789abcdef") != "" || (logo.MIME != "image/png" && logo.MIME != "image/jpeg" && logo.MIME != "image/webp") || logo.SizeBytes < 1 || logo.SizeBytes > 2*1024*1024 || logo.DisplayName == "" || len(logo.DisplayName) > 128 || !safeIdleDisplayName(logo.DisplayName) || !allowedPositions[logo.Position] || positions[logo.Position] || logo.WidthPercent < 5 || logo.WidthPercent > 50 {
			return fmt.Errorf("idle desired logo is invalid")
		}
		positions[logo.Position] = true
	}
	if desired.VideoURL != nil && !validIdleVideo(*desired.VideoURL) {
		return fmt.Errorf("idle desired video is invalid")
	}
	if IdleScreenPayloadHash(desired) != desired.PayloadHash {
		return fmt.Errorf("idle desired hash mismatch")
	}
	return nil
}

func safeIdleDisplayName(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validIdleVideo(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return false
	}
	if parsed.Hostname() == "iframe.mediadelivery.net" {
		return idleVideoEmbedPattern.MatchString(parsed.EscapedPath() + "?" + parsed.RawQuery)
	}
	return idleVideoHostPattern.MatchString(parsed.Hostname()) && strings.HasSuffix(strings.ToLower(parsed.Path), ".mp4") && parsed.RawQuery == ""
}

func regexpColor(value string) bool {
	if len(value) != 7 || value[0] != '#' {
		return false
	}
	for _, character := range value[1:] {
		if !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func PresentationPayloadHash(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

// PresentationPlaylistPayloadHash is the language-neutral ordered playlist
// hash. Labels and URLs are raw-url-base64 encoded and durations are decimal.
func PresentationPlaylistPayloadHash(items []PlaylistItem) string {
	var builder strings.Builder
	builder.WriteString("presentation-playlist-v1\nitemCount=")
	builder.WriteString(base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(len(items)))))
	builder.WriteByte('\n')
	for _, item := range items {
		builder.WriteString("item=")
		builder.WriteString(base64.RawURLEncoding.EncodeToString([]byte(item.Label)))
		builder.WriteByte('\t')
		builder.WriteString(base64.RawURLEncoding.EncodeToString([]byte(item.URL)))
		builder.WriteByte('\t')
		builder.WriteString(strconv.FormatUint(item.DurationSeconds, 10))
		builder.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(digest[:])
}

func validatePlaylistItems(items []PlaylistItem) error {
	if len(items) < 2 || len(items) > 32 {
		return fmt.Errorf("playlist item count is invalid")
	}
	for _, item := range items {
		if len(item.Label) == 0 || !playlistLabelWithinLimit(item.Label) || strings.ContainsAny(item.Label, "\x00\r\n") || item.DurationSeconds < 5 || item.DurationSeconds > 3600 {
			return fmt.Errorf("playlist item is invalid")
		}
		normalized, err := CanonicalPresentationURL(item.URL)
		if err != nil || normalized != item.URL {
			return fmt.Errorf("playlist item URL is invalid")
		}
	}
	return nil
}

// Match the server's JavaScript string length without changing the signed text.
func playlistLabelWithinLimit(value string) bool {
	units := 0
	for _, r := range value {
		units += utf16.RuneLen(r)
		if units > 128 {
			return false
		}
	}
	return true
}

func RuntimeArtifactHash(artifact RuntimeArtifact) string {
	payload := map[string]any{
		"version":          artifact.Version,
		"type":             artifact.Type,
		"status":           artifact.Status,
		"artifactRevision": artifact.ArtifactRevision,
		"sway":             runtimeComponentHashValue(artifact.Sway),
		"novaKeys":         runtimeComponentHashValue(artifact.NOVAKeys),
		"layouts":          artifact.Layouts,
		"blockedReason":    artifact.BlockedReason,
	}
	if artifact.Browser != nil {
		// Keep the nested descriptor as a map so encoding/json's lexical key
		// ordering matches TypeScript stableJson for the cross-language hash.
		payload["browser"] = map[string]any{
			"kiosk":         artifact.Browser.Kiosk,
			"kioskPrinting": artifact.Browser.KioskPrinting,
			"type":          artifact.Browser.Type,
			"version":       artifact.Browser.Version,
		}
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return ""
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func runtimeComponentHashValue(component *RuntimeComponent) any {
	if component == nil {
		return nil
	}
	return map[string]any{
		"revision":       component.Revision,
		"sourceRevision": component.SourceRevision,
		"source":         component.Source,
		"mode":           component.Mode,
		"text":           component.Text,
	}
}

func ValidateRuntimeArtifact(artifact RuntimeArtifact) error {
	if artifact.Version != ProtocolVersion || artifact.Type != "runtime.config" || (artifact.Status != "ready" && artifact.Status != "blocked") || artifact.ArtifactRevision == "" || len(artifact.ArtifactRevision) > 256 || len(artifact.ArtifactHash) != 64 || strings.Trim(artifact.ArtifactHash, "0123456789abcdef") != "" {
		return fmt.Errorf("runtime artifact envelope is invalid")
	}
	if len(artifact.Layouts) > 32 {
		return fmt.Errorf("runtime artifact has too many layouts")
	}
	totalLayoutBytes := 0
	previousCode := ""
	for _, layout := range artifact.Layouts {
		if !isSafeRuntimeLanguageCode(layout.LanguageCode) || (previousCode != "" && layout.LanguageCode <= previousCode) || len([]byte(layout.TOML)) > 200*1024 {
			return fmt.Errorf("runtime artifact layout is invalid")
		}
		for _, character := range layout.TOML {
			if character == 0 || (character < 0x20 && character != '\t' && character != '\n' && character != '\r') || character == 0x7f {
				return fmt.Errorf("runtime artifact layout contains an invalid control")
			}
		}
		totalLayoutBytes += len([]byte(layout.TOML))
		if totalLayoutBytes > 256*1024 {
			return fmt.Errorf("runtime artifact layouts are too large")
		}
		previousCode = layout.LanguageCode
	}
	if artifact.Status == "blocked" {
		if artifact.Sway != nil || artifact.NOVAKeys != nil || artifact.BlockedReason == nil || (*artifact.BlockedReason != "runtime-presentation-assignment-missing" && *artifact.BlockedReason != "runtime-presentation-marker-unresolved") {
			return fmt.Errorf("blocked runtime artifact is invalid")
		}
	} else {
		if artifact.Sway == nil || artifact.NOVAKeys == nil || artifact.BlockedReason != nil || !validateRuntimeComponent(artifact.Sway) || !validateRuntimeComponent(artifact.NOVAKeys) {
			return fmt.Errorf("ready runtime artifact is invalid")
		}
	}
	if artifact.Browser != nil && (artifact.Browser.Version != 1 || artifact.Browser.Type != "direct-chromium-v1") {
		return fmt.Errorf("runtime artifact browser descriptor is invalid")
	}
	if RuntimeArtifactHash(artifact) != artifact.ArtifactHash {
		return fmt.Errorf("runtime artifact hash does not match content")
	}
	return nil
}

func validateRuntimeComponent(component *RuntimeComponent) bool {
	if (component.Source != "global" && component.Source != "custom") || (component.Mode != "simple" && component.Mode != "raw") || len([]byte(component.Text)) > 64*1024 {
		return false
	}
	for _, character := range component.Text {
		if character == 0 || (character < 0x20 && character != '\t' && character != '\n' && character != '\r') || character == 0x7f {
			return false
		}
	}
	return true
}

func isSafeRuntimeLanguageCode(value string) bool {
	if len(value) < 2 || len(value) > 32 {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if len(part) < 2 || len(part) > 12 {
			return false
		}
		for _, character := range part {
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					return false
				}
			}
		}
	}
	return true
}

func validateResult(result Result, request Request, now time.Time) error {
	if result.Version != ProtocolVersion || result.Type != "bootstrap.enrollment.result" || result.Status != "pending" {
		return fmt.Errorf("unsupported enrollment response")
	}
	if result.EnrollmentID == "" || result.DeviceID == "" || result.ComparisonValue == "" || len(result.ComparisonValue) > 128 {
		return fmt.Errorf("enrollment response is incomplete")
	}
	if result.DeviceID != request.DeviceID {
		return fmt.Errorf("enrollment response device does not match request")
	}
	expires, err := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || !expires.After(now) {
		return fmt.Errorf("enrollment response expiry is invalid")
	}
	if result.ExpiresAt != request.ExpiresAt {
		return fmt.Errorf("enrollment response expiry does not match request")
	}
	return nil
}

func decodeResult(data []byte, request Request, now time.Time) (Result, error) {
	var result Result
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Result{}, fmt.Errorf("malformed enrollment response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Result{}, fmt.Errorf("malformed enrollment response")
	}
	if err := validateResult(result, request, now); err != nil {
		return Result{}, err
	}
	return result, nil
}
