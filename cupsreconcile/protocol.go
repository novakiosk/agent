package cupsreconcile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	Version                  = 1
	Version2                 = 2
	DesiredType              = "printer.desired"
	AckType                  = "printer.desired.ack"
	MaxQueues                = 32
	MaxOptions               = 32
	MaxMessageBytes          = 32 * 1024
	ModeExisting             = "existing"
	ModeRemote               = "remote"
	ModeDirect               = "direct"
	ResultApplied            = "applied"
	ResultFailed             = "failed"
	ErrorApply               = "cups_apply_failed"
	ErrorHelper              = "cups_helper_unavailable"
	ErrorInvalid             = "printer_desired_invalid"
	ErrorEndpoint            = "printer_endpoint_unavailable"
	Capability               = "printer-reconcile-v1"
	CapabilityV2             = "printer-reconcile-v2"
	ConnectionZebraAppSocket = "zebra-appsocket-9100"
	DriverZebraZPL           = "zebra-zpl"
	DriverZebraZPLURI        = "drv:///sample.drv/zebra.ppd"
	HelperRequestName        = "cups-desired.json"
	HelperResultName         = "cups-result.json"
)

type Option struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Queue struct {
	PrinterID string   `json:"printerId"`
	LocalName string   `json:"localName"`
	Mode      string   `json:"mode"`
	RemoteURI string   `json:"remoteUri,omitempty"`
	Options   []Option `json:"options"`
	// Direct queue fields are only accepted in the v2 direct profile. They are
	// deliberately optional here so v1 kiosk proxy payloads remain wire-safe.
	PrivateIP         string       `json:"privateIp,omitempty"`
	ConnectionProfile string       `json:"connectionProfile,omitempty"`
	DriverProfile     string       `json:"driverProfile,omitempty"`
	DisplayName       string       `json:"displayName,omitempty"`
	Location          string       `json:"location,omitempty"`
	CustomMedia       *CustomMedia `json:"customMedia,omitempty"`
}

// CustomMedia holds dimensions in millimetres. The direct helper validates
// them against the installed PPD bounds before setting the media size.
type CustomMedia struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
	Unit   string  `json:"unit"`
}

type DesiredV2 struct {
	Version     int     `json:"version"`
	Type        string  `json:"type"`
	SessionID   string  `json:"sessionId"`
	DeviceID    string  `json:"deviceId"`
	DesiredHash string  `json:"desiredHash"`
	Queues      []Queue `json:"queues"`
}

type Desired struct {
	DefaultQueue *string `json:"defaultQueue,omitempty"`
	Version      int     `json:"version"`
	Type         string  `json:"type"`
	SessionID    string  `json:"sessionId"`
	DeviceID     string  `json:"deviceId"`
	DesiredHash  string  `json:"desiredHash"`
	Queues       []Queue `json:"queues"`
}

type Ack struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	Profile       string `json:"profile"`
	SessionID     string `json:"sessionId"`
	DeviceID      string `json:"deviceId"`
	DesiredHash   string `json:"desiredHash"`
	Result        string `json:"result"`
	ErrorCategory string `json:"errorCategory,omitempty"`
	ObservedAt    string `json:"observedAt"`
	Sequence      uint64 `json:"sequence"`
	Signature     string `json:"signature"`
}

type HelperRequest struct {
	DefaultQueue *string `json:"defaultQueue,omitempty"`
	Version      int     `json:"version"`
	Type         string  `json:"type"`
	DesiredHash  string  `json:"desiredHash"`
	Queues       []Queue `json:"queues"`
}

type HelperResult struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	DesiredHash   string `json:"desiredHash"`
	Result        string `json:"result"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

func DecodeDesired(data []byte, sessionID, deviceID string) (Desired, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return Desired{}, errors.New("cups reconcile: desired message exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var desired Desired
	if err := decoder.Decode(&desired); err != nil {
		return Desired{}, errors.New("cups reconcile: malformed desired message")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Desired{}, errors.New("cups reconcile: malformed desired message")
	}
	if desired.SessionID != sessionID || desired.DeviceID != deviceID {
		return Desired{}, errors.New("cups reconcile: desired identity mismatch")
	}
	if err := desired.Validate(); err != nil {
		return Desired{}, err
	}
	return desired.Normalize(), nil
}

func (desired Desired) Validate() error {
	if desired.Version != Version || desired.Type != DesiredType || !safeID(desired.SessionID, 128) || !safeID(desired.DeviceID, 128) || !hashValue(desired.DesiredHash) || len(desired.Queues) > MaxQueues {
		return errors.New("cups reconcile: invalid desired message")
	}
	seenPrinters := make(map[string]struct{}, len(desired.Queues))
	seenNames := make(map[string]struct{}, len(desired.Queues))
	for _, queue := range desired.Queues {
		if !safeID(queue.PrinterID, 128) || !safeQueueName(queue.LocalName) || (queue.Mode != ModeExisting && queue.Mode != ModeRemote) || len(queue.Options) > MaxOptions {
			return errors.New("cups reconcile: invalid desired queue")
		}
		if queue.PrivateIP != "" || queue.ConnectionProfile != "" || queue.DriverProfile != "" || queue.DisplayName != "" || queue.Location != "" || queue.CustomMedia != nil {
			return errors.New("cups reconcile: direct queue fields require v2")
		}
		if _, duplicate := seenPrinters[queue.PrinterID]; duplicate {
			return errors.New("cups reconcile: duplicate printer")
		}
		if _, duplicate := seenNames[strings.ToLower(queue.LocalName)]; duplicate {
			return errors.New("cups reconcile: duplicate local queue")
		}
		seenPrinters[queue.PrinterID] = struct{}{}
		seenNames[strings.ToLower(queue.LocalName)] = struct{}{}
		if queue.Mode == ModeExisting && queue.RemoteURI != "" {
			return errors.New("cups reconcile: existing queue has remote URI")
		}
		if queue.Mode == ModeRemote {
			if !strings.HasPrefix(queue.LocalName, "NOVA_") || !safeRemoteURI(queue.RemoteURI) || len(queue.Options) != 0 {
				return errors.New("cups reconcile: invalid remote queue")
			}
		}
		optionNames := make(map[string]struct{}, len(queue.Options))
		for _, option := range queue.Options {
			if !safeOptionToken(option.Name, 64) || !safeOptionToken(option.Value, 128) {
				return errors.New("cups reconcile: invalid queue option")
			}
			if _, duplicate := optionNames[option.Name]; duplicate {
				return errors.New("cups reconcile: duplicate queue option")
			}
			optionNames[option.Name] = struct{}{}
		}
	}
	if desired.DefaultQueue != nil && *desired.DefaultQueue != "" {
		found := false
		for _, queue := range desired.Queues {
			if queue.LocalName == *desired.DefaultQueue {
				found = true
			}
		}
		if !found {
			return errors.New("cups reconcile: default queue is not desired")
		}
	}
	expected, err := desired.PayloadHash()
	if err != nil || expected != desired.DesiredHash {
		return errors.New("cups reconcile: desired hash mismatch")
	}
	return nil
}

// DecodeDesiredV2 parses the direct central-queue protocol. It is separate
// from DecodeDesired so the kiosk profile cannot accept
// direct queue fields.
func DecodeDesiredV2(data []byte, sessionID, deviceID string) (DesiredV2, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return DesiredV2{}, errors.New("cups reconcile: desired v2 message exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var desired DesiredV2
	if err := decoder.Decode(&desired); err != nil {
		return DesiredV2{}, errors.New("cups reconcile: malformed desired v2 message")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return DesiredV2{}, errors.New("cups reconcile: malformed desired v2 message")
	}
	if desired.SessionID != sessionID || desired.DeviceID != deviceID {
		return DesiredV2{}, errors.New("cups reconcile: desired identity mismatch")
	}
	if err := desired.Validate(); err != nil {
		return DesiredV2{}, err
	}
	return desired.Normalize(), nil
}

func (desired DesiredV2) Validate() error {
	if desired.Version != Version2 || desired.Type != DesiredType || !safeID(desired.SessionID, 128) || !safeID(desired.DeviceID, 128) || !hashValue(desired.DesiredHash) || len(desired.Queues) > MaxQueues {
		return errors.New("cups reconcile: invalid desired v2 message")
	}
	seenPrinters, seenNames := map[string]struct{}{}, map[string]struct{}{}
	for _, queue := range desired.Queues {
		if !safeID(queue.PrinterID, 128) || !safeDirectQueueName(queue.LocalName) || queue.Mode != ModeDirect || len(queue.Options) > MaxOptions {
			return errors.New("cups reconcile: invalid direct queue")
		}
		if _, ok := seenPrinters[queue.PrinterID]; ok {
			return errors.New("cups reconcile: duplicate printer")
		}
		seenPrinters[queue.PrinterID] = struct{}{}
		if _, ok := seenNames[strings.ToLower(queue.LocalName)]; ok {
			return errors.New("cups reconcile: duplicate local queue")
		}
		seenNames[strings.ToLower(queue.LocalName)] = struct{}{}
		if !privateIPv4(queue.PrivateIP) || queue.ConnectionProfile != ConnectionZebraAppSocket || queue.DriverProfile != DriverZebraZPL {
			return errors.New("cups reconcile: invalid direct profile")
		}
		if !boundedText(queue.DisplayName, 128) || !boundedText(queue.Location, 128) {
			return errors.New("cups reconcile: invalid direct metadata")
		}
		if queue.RemoteURI != "" {
			return errors.New("cups reconcile: direct queue has remote URI")
		}
		if queue.CustomMedia != nil && !validCustomMedia(*queue.CustomMedia) {
			return errors.New("cups reconcile: invalid custom media")
		}
		seenOptions := map[string]struct{}{}
		for _, option := range queue.Options {
			if !safeOptionToken(option.Name, 64) || !safeOptionToken(option.Value, 128) {
				return errors.New("cups reconcile: invalid direct option")
			}
			if _, ok := seenOptions[option.Name]; ok {
				return errors.New("cups reconcile: duplicate direct option")
			}
			seenOptions[option.Name] = struct{}{}
		}
	}
	expected, err := desired.PayloadHash()
	if err != nil || expected != desired.DesiredHash {
		return errors.New("cups reconcile: desired v2 hash mismatch")
	}
	return nil
}

func (desired DesiredV2) Normalize() DesiredV2 {
	normalized := desired
	normalized.Queues = append([]Queue(nil), desired.Queues...)
	for i := range normalized.Queues {
		normalized.Queues[i].Options = append([]Option(nil), normalized.Queues[i].Options...)
		sort.Slice(normalized.Queues[i].Options, func(a, b int) bool {
			return normalized.Queues[i].Options[a].Name < normalized.Queues[i].Options[b].Name
		})
	}
	sort.Slice(normalized.Queues, func(a, b int) bool { return normalized.Queues[a].PrinterID < normalized.Queues[b].PrinterID })
	return normalized
}

func (desired DesiredV2) CanonicalPayload() ([]byte, error) {
	normalized := desired.Normalize()
	var b strings.Builder
	b.WriteString("printer-desired-canonical-v2\n")
	writeField(&b, "version", "2")
	writeField(&b, "type", DesiredType)
	writeField(&b, "queueCount", fmt.Sprintf("%d", len(normalized.Queues)))
	for _, q := range normalized.Queues {
		b.WriteString("queue=")
		b.WriteString(encode(q.PrinterID))
		b.WriteByte('\t')
		b.WriteString(encode(q.LocalName))
		b.WriteByte('\t')
		b.WriteString(q.Mode)
		b.WriteByte('\t')
		b.WriteString(encode(q.PrivateIP))
		b.WriteByte('\t')
		b.WriteString(encode(q.ConnectionProfile))
		b.WriteByte('\t')
		b.WriteString(encode(q.DriverProfile))
		b.WriteByte('\t')
		b.WriteString(encode(q.DisplayName))
		b.WriteByte('\t')
		b.WriteString(encode(q.Location))
		b.WriteByte('\t')
		if q.CustomMedia == nil {
			b.WriteString(encode(""))
		} else {
			// Keep this wire fragment explicit: JSON object insertion order is
			// not part of the input contract, while the canonical hash is.
			encoded, _ := json.Marshal(struct {
				Width  float64 `json:"width"`
				Height float64 `json:"height"`
				Unit   string  `json:"unit"`
			}{Width: q.CustomMedia.Width, Height: q.CustomMedia.Height, Unit: q.CustomMedia.Unit})
			b.WriteString(encode(string(encoded)))
		}
		b.WriteByte('\t')
		b.WriteString(fmt.Sprintf("%d", len(q.Options)))
		b.WriteByte('\n')
		for _, o := range q.Options {
			b.WriteString("option=")
			b.WriteString(encode(q.PrinterID))
			b.WriteByte('\t')
			b.WriteString(encode(o.Name))
			b.WriteByte('\t')
			b.WriteString(encode(o.Value))
			b.WriteByte('\n')
		}
	}
	payload := []byte(b.String())
	if len(payload) > MaxMessageBytes {
		return nil, errors.New("cups reconcile: canonical desired v2 exceeds bound")
	}
	return payload, nil
}
func (desired DesiredV2) PayloadHash() (string, error) {
	payload, err := desired.CanonicalPayload()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func safeDirectQueueName(value string) bool {
	return strings.HasPrefix(value, "NOVA_") && len(value) <= 127 && safeQueueName(value)
}
func boundedText(value string, limit int) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return false
	}
	// Match the server's JavaScript UTF-16 code-unit limit.
	units := 0
	for _, r := range value {
		units += utf16.RuneLen(r)
		if units > limit {
			return false
		}
	}
	return true
}
func privateIPv4(value string) bool {
	parsed := net.ParseIP(value)
	if parsed == nil || parsed.To4() == nil || strings.Contains(value, ":") {
		return false
	}
	octets := strings.Split(value, ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		if o == "" || (len(o) > 1 && o[0] == '0') {
			return false
		}
		n := 0
		for _, r := range o {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return false
		}
	}
	return parsed.IsPrivate()
}
func validCustomMedia(media CustomMedia) bool {
	if media.Unit != "mm" || !finite(media.Width) || !finite(media.Height) || media.Width < 12.7 || media.Width > 203.2 || media.Height < 12.7 || media.Height > 1270 {
		return false
	}
	return decimalPlaces(media.Width) <= 2 && decimalPlaces(media.Height) <= 2
}
func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
func decimalPlaces(value float64) int {
	text := strconv.FormatFloat(value, 'f', -1, 64)
	if dot := strings.IndexByte(text, '.'); dot >= 0 {
		return len(text) - dot - 1
	}
	return 0
}

func (desired Desired) Normalize() Desired {
	normalized := desired
	normalized.Queues = append([]Queue(nil), desired.Queues...)
	for index := range normalized.Queues {
		normalized.Queues[index].Options = append([]Option(nil), normalized.Queues[index].Options...)
		sort.Slice(normalized.Queues[index].Options, func(left, right int) bool {
			return normalized.Queues[index].Options[left].Name < normalized.Queues[index].Options[right].Name
		})
	}
	sort.Slice(normalized.Queues, func(left, right int) bool {
		return normalized.Queues[left].PrinterID < normalized.Queues[right].PrinterID
	})
	return normalized
}

func (desired Desired) CanonicalPayload() ([]byte, error) {
	normalized := desired.Normalize()
	var builder strings.Builder
	builder.WriteString("printer-desired-canonical-v1\n")
	writeField(&builder, "version", "1")
	writeField(&builder, "type", DesiredType)
	writeField(&builder, "queueCount", fmt.Sprintf("%d", len(normalized.Queues)))
	if normalized.DefaultQueue != nil {
		writeField(&builder, "defaultQueue", *normalized.DefaultQueue)
	}
	for _, queue := range normalized.Queues {
		builder.WriteString("queue=")
		builder.WriteString(encode(queue.PrinterID))
		builder.WriteByte('\t')
		builder.WriteString(encode(queue.LocalName))
		builder.WriteByte('\t')
		builder.WriteString(queue.Mode)
		builder.WriteByte('\t')
		builder.WriteString(encode(queue.RemoteURI))
		builder.WriteByte('\t')
		builder.WriteString(fmt.Sprintf("%d", len(queue.Options)))
		builder.WriteByte('\n')
		for _, option := range queue.Options {
			builder.WriteString("option=")
			builder.WriteString(encode(queue.PrinterID))
			builder.WriteByte('\t')
			builder.WriteString(encode(option.Name))
			builder.WriteByte('\t')
			builder.WriteString(encode(option.Value))
			builder.WriteByte('\n')
		}
	}
	payload := []byte(builder.String())
	if len(payload) > MaxMessageBytes {
		return nil, errors.New("cups reconcile: canonical desired exceeds bound")
	}
	return payload, nil
}

func (desired Desired) PayloadHash() (string, error) {
	payload, err := desired.CanonicalPayload()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func AckCanonical(ack Ack) []byte {
	var builder strings.Builder
	builder.WriteString("nova-canonical-v1\ntype=")
	builder.WriteString(encode(AckType))
	builder.WriteByte('\n')
	writeField(&builder, "version", "1")
	writeField(&builder, "profile", ack.Profile)
	writeField(&builder, "sessionId", ack.SessionID)
	writeField(&builder, "deviceId", ack.DeviceID)
	writeField(&builder, "desiredHash", ack.DesiredHash)
	writeField(&builder, "result", ack.Result)
	writeField(&builder, "errorCategory", ack.ErrorCategory)
	writeField(&builder, "observedAt", ack.ObservedAt)
	writeField(&builder, "sequence", fmt.Sprintf("%d", ack.Sequence))
	return []byte(builder.String())
}

func AckCanonicalV2(ack Ack) []byte {
	var builder strings.Builder
	builder.WriteString("nova-canonical-v2\ntype=")
	builder.WriteString(encode(AckType))
	builder.WriteByte('\n')
	writeField(&builder, "version", strconv.Itoa(Version2))
	writeField(&builder, "profile", ack.Profile)
	writeField(&builder, "sessionId", ack.SessionID)
	writeField(&builder, "deviceId", ack.DeviceID)
	writeField(&builder, "desiredHash", ack.DesiredHash)
	writeField(&builder, "result", ack.Result)
	writeField(&builder, "errorCategory", ack.ErrorCategory)
	writeField(&builder, "observedAt", ack.ObservedAt)
	writeField(&builder, "sequence", fmt.Sprintf("%d", ack.Sequence))
	return []byte(builder.String())
}

func safeRemoteURI(value string) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "ipp" && parsed.Scheme != "ipps") || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.EscapedPath(), "/printers/") {
		return false
	}
	return true
}

func safeQueueName(value string) bool { return safeOptionToken(value, 127) }

func safeOptionToken(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("._-+", character) {
			continue
		}
		return false
	}
	return true
}

func safeID(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func hashValue(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func writeField(builder *strings.Builder, name, value string) {
	builder.WriteString(name)
	builder.WriteByte('=')
	builder.WriteString(encode(value))
	builder.WriteByte('\n')
}

func encode(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
