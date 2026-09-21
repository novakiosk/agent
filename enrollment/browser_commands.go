package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const BrowserCommandCapability = "browser-command-v1"
const BrowserCommandType = "browser.command"
const BrowserCommandResultType = "browser.command.result"

var browserCommandUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var browserCommandHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var browserCommandTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)
var browserCommandErrors = map[string]bool{"browser-unavailable": true, "browser-unsupported": true, "browser-navigation": true, "browser-observation": true, "browser-zoom": true, "browser-restart": true, "browser-command-expired": true}
var BrowserZoomAllowlist = map[int]bool{50: true, 67: true, 75: true, 80: true, 90: true, 100: true, 110: true, 125: true, 150: true, 175: true, 200: true}

type BrowserCommand struct {
	Version     int    `json:"version"`
	Type        string `json:"type"`
	Profile     string `json:"profile"`
	CommandID   string `json:"commandId"`
	Action      string `json:"action"`
	ZoomPercent *int   `json:"zoomPercent"`
	IssuedAt    string `json:"issuedAt"`
	ExpiresAt   string `json:"expiresAt"`
	PayloadHash string `json:"payloadHash"`
}

type BrowserCommandResult struct {
	Version       int     `json:"version"`
	Type          string  `json:"type"`
	Profile       string  `json:"profile"`
	SessionID     string  `json:"sessionId"`
	DeviceID      string  `json:"deviceId"`
	CommandID     string  `json:"commandId"`
	Action        string  `json:"action"`
	PayloadHash   string  `json:"payloadHash"`
	Result        string  `json:"result"`
	ErrorCategory *string `json:"errorCategory"`
	ObservedURL   string  `json:"observedUrl"`
	ZoomPercent   *int    `json:"zoomPercent"`
	ObservedAt    string  `json:"observedAt"`
	Sequence      uint64  `json:"sequence"`
	Signature     string  `json:"signature"`
}

func BrowserCommandCanonical(command BrowserCommand) []byte {
	zoom := ""
	if command.ZoomPercent != nil {
		zoom = fmt.Sprintf("%d", *command.ZoomPercent)
	}
	return CanonicalV1(BrowserCommandType,
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"commandId", command.CommandID}, CanonicalField{"action", command.Action},
		CanonicalField{"zoomPercent", zoom}, CanonicalField{"issuedAt", command.IssuedAt}, CanonicalField{"expiresAt", command.ExpiresAt})
}

func BrowserCommandHash(command BrowserCommand) string {
	sum := sha256.Sum256(BrowserCommandCanonical(command))
	return hex.EncodeToString(sum[:])
}

func BrowserCommandResultCanonical(result BrowserCommandResult) []byte {
	err := ""
	if result.ErrorCategory != nil {
		err = *result.ErrorCategory
	}
	zoom := ""
	if result.ZoomPercent != nil {
		zoom = fmt.Sprintf("%d", *result.ZoomPercent)
	}
	return CanonicalV1(BrowserCommandResultType,
		CanonicalField{"version", "1"}, CanonicalField{"profile", ProvisionalIdentityProfile},
		CanonicalField{"sessionId", result.SessionID}, CanonicalField{"deviceId", result.DeviceID}, CanonicalField{"commandId", result.CommandID},
		CanonicalField{"action", result.Action}, CanonicalField{"payloadHash", result.PayloadHash}, CanonicalField{"result", result.Result},
		CanonicalField{"errorCategory", err}, CanonicalField{"observedUrl", result.ObservedURL}, CanonicalField{"zoomPercent", zoom},
		CanonicalField{"observedAt", result.ObservedAt}, CanonicalField{"sequence", fmt.Sprintf("%d", result.Sequence)})
}

func (command BrowserCommand) Validate(now time.Time, allowExpired bool) error {
	if command.Version != ProtocolVersion || command.Type != BrowserCommandType || command.Profile != ProvisionalIdentityProfile || !browserCommandUUID.MatchString(command.CommandID) {
		return fmt.Errorf("browser command identity is invalid")
	}
	if command.Action != "reload" && command.Action != "return-to-assigned" && command.Action != "set-zoom" && command.Action != "restart-browser" {
		return fmt.Errorf("browser command action is invalid")
	}
	if command.Action == "set-zoom" {
		if command.ZoomPercent == nil || !BrowserZoomAllowlist[*command.ZoomPercent] {
			return fmt.Errorf("browser command zoom is invalid")
		}
	} else if command.ZoomPercent != nil {
		return fmt.Errorf("browser command zoom is not allowed")
	}
	issued, err := parseBrowserCommandTimestamp(command.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parseBrowserCommandTimestamp(command.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 15*time.Minute {
		return fmt.Errorf("browser command expiry is invalid")
	}
	if !allowExpired && (now.After(expires.Add(5*time.Minute)) || now.Before(issued.Add(-5*time.Minute))) {
		return fmt.Errorf("browser command is outside its time window")
	}
	if len(command.PayloadHash) != 64 || BrowserCommandHash(command) != command.PayloadHash {
		return fmt.Errorf("browser command hash is invalid")
	}
	return nil
}

func (result BrowserCommandResult) Validate() error {
	if result.Version != ProtocolVersion || result.Type != BrowserCommandResultType || result.Profile != ProvisionalIdentityProfile || result.SessionID == "" || len(result.SessionID) > 128 || result.DeviceID == "" || len(result.DeviceID) > 128 || !browserCommandUUID.MatchString(result.CommandID) || (result.Result != "applied" && result.Result != "failed") || result.ObservedAt == "" || result.Sequence == 0 || len(result.ObservedURL) > 2048 {
		return fmt.Errorf("browser command result is invalid")
	}
	if result.Action != "reload" && result.Action != "return-to-assigned" && result.Action != "set-zoom" && result.Action != "restart-browser" {
		return fmt.Errorf("browser command result action is invalid")
	}
	if !browserCommandHashPattern.MatchString(result.PayloadHash) {
		return fmt.Errorf("browser command result hash is invalid")
	}
	if result.Action == "set-zoom" {
		if result.Result == "applied" && (result.ZoomPercent == nil || !BrowserZoomAllowlist[*result.ZoomPercent]) {
			return fmt.Errorf("set-zoom result must report its accepted zoom")
		}
		if result.Result == "failed" && result.ZoomPercent != nil {
			return fmt.Errorf("failed set-zoom result must not report an accepted zoom")
		}
	} else if result.ZoomPercent != nil {
		return fmt.Errorf("browser command result zoom is not allowed for this action")
	}
	if observed, err := parseBrowserCommandTimestamp(result.ObservedAt); err != nil || observed.IsZero() {
		return fmt.Errorf("browser command result timestamp is invalid")
	}
	if result.Result == "applied" && result.ErrorCategory != nil {
		return fmt.Errorf("applied browser command cannot have an error")
	}
	if result.Result == "failed" && (result.ErrorCategory == nil || !browserCommandErrors[*result.ErrorCategory]) {
		return fmt.Errorf("browser command failure category is invalid")
	}
	return nil
}

// parseBrowserCommandTimestamp mirrors the control-plane canonical timestamp
// contract: UTC RFC3339 with an optional 1-9 digit fractional second and no
// offset spelling. Go's RFC3339Nano formatter emits the same forms.
func parseBrowserCommandTimestamp(value string) (time.Time, error) {
	if !browserCommandTimestampPattern.MatchString(value) {
		return time.Time{}, fmt.Errorf("browser command timestamp is invalid")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return time.Time{}, fmt.Errorf("browser command timestamp is invalid")
	}
	fraction := ""
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		fraction = value[dot+1 : len(value)-1]
	}
	if fraction != "" && strings.HasSuffix(fraction, "0") {
		return time.Time{}, fmt.Errorf("browser command timestamp is not canonical")
	}
	return parsed, nil
}
