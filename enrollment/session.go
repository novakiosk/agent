package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/cupsreconcile"
)

const (
	sessionHandshakeTimeout = 10 * time.Second
	sessionMessageTimeout   = 15 * time.Second
)

type SessionProtocolError struct{ Code string }

func (err *SessionProtocolError) Error() string { return "managed session rejected: " + err.Code }

func permanentSessionError(err error) bool {
	var protocolErr *SessionProtocolError
	if !errors.As(err, &protocolErr) {
		return false
	}
	switch protocolErr.Code {
	case "IDENTITY_REVOKED", "IDENTITY_NOT_APPROVED", "PROVISIONAL_PROFILE_DISABLED", "IDENTITY_INVALID", "CHALLENGE_INVALID", "CHALLENGE_EXPIRED", "DESIRED_ACK_INVALID", "DESIRED_ACK_NOT_ASSIGNED", "DESIRED_ACK_OUT_OF_ORDER", "RUNTIME_ACK_INVALID", "PRINTER_REPORT_INVALID", "PRINTER_REPORT_CONFLICT", "PRINTER_REPORT_OUT_OF_ORDER", "PRINTER_RECONCILE_ACK_INVALID", "PRINTER_RECONCILE_ACK_CONFLICT", "PRINTER_RECONCILE_ACK_OUT_OF_ORDER", "HOST_INVENTORY_INVALID", "HOST_INVENTORY_CONFLICT", "HOST_INVENTORY_OUT_OF_ORDER", "HOST_INVENTORY_NOT_ALLOWED", "OPERATION_ACK_INVALID", "OPERATION_ACK_CONFLICT", "OPERATION_RESULT_INVALID", "OPERATION_RESULT_CONFLICT", "OPERATION_NOT_ALLOWED", "RUNTIME_NOT_ALLOWED", "DESIRED_NOT_ALLOWED":
		return true
	case "PRINTER_STATISTICS_NOT_NEGOTIATED", "PRINTER_STATISTICS_INVALID", "PRINTER_STATISTICS_CONFLICT", "PRINTER_STATISTICS_OUT_OF_ORDER", "PRINTER_JOBS_NOT_NEGOTIATED", "PRINTER_JOBS_INVALID", "PRINTER_JOBS_CONFLICT", "PRINTER_JOBS_OUT_OF_ORDER", "PRINTER_JOB_COMMAND_NOT_NEGOTIATED", "PRINTER_JOB_COMMAND_INVALID", "PRINTER_JOB_COMMAND_CONFLICT", "PRINTER_JOB_COMMAND_OUT_OF_ORDER":
		return true
	default:
		return false
	}
}

type sessionChallenge struct {
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
}

type sessionAccepted struct {
	Version           int    `json:"version"`
	Type              string `json:"type"`
	Profile           string `json:"profile"`
	SessionID         string `json:"sessionId"`
	EnrollmentID      string `json:"enrollmentId"`
	IdentityBindingID string `json:"identityBindingId"`
	DeviceID          string `json:"deviceId"`
}

type heartbeatAccepted struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Sequence  uint64 `json:"sequence"`
}

type SessionOptions struct {
	HeartbeatSequence   uint64
	WriteTimeout        time.Duration
	DisplayModeObserver func() DisplayMode
}

type SessionEvidence struct {
	SessionID         string
	IdentityBindingID string
	HeartbeatSequence uint64
	LastHeartbeatAt   string
	DisplayMode       DisplayMode
}

func (client Client) observeDisplayMode(observer func() DisplayMode) DisplayMode {
	if observer == nil {
		observer = client.DisplayModeObserver
	}
	if observer == nil {
		observer = ObserveDisplayMode
	}
	mode := observer()
	if !mode.Valid() {
		return DisplayModeUnknown
	}
	return mode
}

func validateDesiredSnapshotAt(snapshot DesiredSnapshot, sessionID, deviceID string, operationNow time.Time, allowExpiredOperation, allowExpiredBrowser bool) error {
	if snapshot.Version != ProtocolVersion || snapshot.Type != "desired.snapshot" || snapshot.SessionID != sessionID || snapshot.DeviceID != deviceID {
		return fmt.Errorf("desired snapshot identity is invalid")
	}
	if snapshot.Idle != nil {
		if err := ValidateIdleDesired(*snapshot.Idle); err != nil {
			return err
		}
	}
	if snapshot.RemoteDesktop != nil {
		if err := ValidateRemoteDesktopDesired(*snapshot.RemoteDesktop, operationNow); err != nil {
			return err
		}
	}
	if snapshot.RemoteDesktopPoll != nil && (snapshot.RemoteDesktopPoll.IntervalMs < 750 || snapshot.RemoteDesktopPoll.IntervalMs > 5_000) {
		return fmt.Errorf("remote desktop poll policy is invalid")
	}
	if snapshot.Desired == nil {
		if snapshot.Runtime != nil {
			if err := ValidateRuntimeArtifact(*snapshot.Runtime); err != nil {
				return err
			}
		}
	} else {
		if snapshot.Desired.GroupID == "" || snapshot.Desired.RevisionID == "" || snapshot.Desired.Revision == 0 || len(snapshot.Desired.PayloadHash) != 64 {
			return fmt.Errorf("desired snapshot content is invalid")
		}
		switch snapshot.Desired.Type {
		case "single-url-v1":
			normalized, err := CanonicalPresentationURL(snapshot.Desired.URL)
			if err != nil || normalized != snapshot.Desired.URL || len(snapshot.Desired.Items) != 0 || PresentationPayloadHash(snapshot.Desired.URL) != snapshot.Desired.PayloadHash {
				return fmt.Errorf("desired snapshot URL is invalid")
			}
		case "playlist-v1":
			if snapshot.Desired.URL != "" || validatePlaylistItems(snapshot.Desired.Items) != nil || PresentationPlaylistPayloadHash(snapshot.Desired.Items) != snapshot.Desired.PayloadHash {
				return fmt.Errorf("desired snapshot playlist is invalid")
			}
		default:
			return fmt.Errorf("desired snapshot content type is invalid")
		}
		if snapshot.Runtime != nil {
			if err := ValidateRuntimeArtifact(*snapshot.Runtime); err != nil {
				return err
			}
		}
	}
	if snapshot.Operation != nil {
		var err error
		if allowExpiredOperation {
			err = snapshot.Operation.ValidateForReplay(operationNow)
		} else {
			err = snapshot.Operation.Validate(operationNow)
		}
		if err != nil {
			return fmt.Errorf("operation command is invalid")
		}
	}
	if snapshot.BrowserCommand != nil {
		if err := snapshot.BrowserCommand.Validate(operationNow, allowExpiredBrowser); err != nil {
			return fmt.Errorf("browser command is invalid")
		}
	}
	return nil
}

func websocketURL(instance string) (string, error) {
	parsed, err := validateInstance(instance)
	if err != nil {
		return "", err
	}
	parsed.Scheme = "wss"
	parsed.Path = SessionPath
	return parsed.String(), nil
}

func (client Client) websocketDialer() (*websocket.Dialer, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if client.CAPath != "" {
		data, readErr := os.ReadFile(client.CAPath)
		if readErr != nil || !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("configured CA certificate could not be loaded")
		}
	}
	return &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		HandshakeTimeout: sessionHandshakeTimeout,
	}, nil
}

func readSessionMessage(ctx context.Context, connection *websocket.Conn, destination any) error {
	return readSessionMessageBounded(ctx, connection, destination, MaxCanonicalBytes)
}

func readRuntimeSessionMessage(ctx context.Context, connection *websocket.Conn, destination any) error {
	return readSessionMessageBounded(ctx, connection, destination, MaxMessageBytes)
}

func readSessionMessageBounded(ctx context.Context, connection *websocket.Conn, destination any, maxBytes int) error {
	deadline := time.Now().Add(sessionMessageTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set managed session read deadline")
	}
	_, data, err := connection.ReadMessage()
	if err != nil {
		return fmt.Errorf("read managed session message")
	}
	if len(data) > maxBytes {
		return fmt.Errorf("managed session message is too large")
	}
	if err := decodeStrictBounded(data, destination, maxBytes); err != nil {
		var envelope struct {
			Version int    `json:"version"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		}
		if decodeErr := decodeStrict(data, &envelope); decodeErr == nil && envelope.Type == "session.rejected" && envelope.Code != "" {
			return &SessionProtocolError{Code: envelope.Code}
		}
		return err
	}
	return nil
}

func validateSessionChallenge(challenge sessionChallenge, state State, identity Identity, instance *url.URL, now time.Time) error {
	if challenge.Version != ProtocolVersion || challenge.Type != "session.challenge" || challenge.Profile != ProvisionalIdentityProfile ||
		challenge.SessionID == "" || challenge.ChallengeID == "" || challenge.EnrollmentID != state.EnrollmentID ||
		challenge.IdentityBindingID == "" || challenge.DeviceID != state.DeviceID ||
		challenge.PublicIdentityRef != identity.PublicIdentityRef || challenge.Nonce == "" ||
		challenge.Audience != instance.String() {
		return fmt.Errorf("managed session challenge is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	if err != nil || !expires.After(now) {
		return fmt.Errorf("managed session challenge has expired")
	}
	return nil
}

func writeSessionMessage(connection *websocket.Conn, value any, timeout time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxMessageBytes {
		return fmt.Errorf("managed session message is too large")
	}
	if timeout <= 0 {
		timeout = sessionMessageTimeout
	}
	if err := connection.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set managed session write deadline")
	}
	if err := connection.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("write managed session message")
	}
	return nil
}

// openManagedSession performs the authenticated handshake and leaves the
// socket open for periodic heartbeats. The cleanup function also stops the
// context watcher used to unblock reads during reconnect/cancellation.
func (client Client) openManagedSession(ctx context.Context, state State, identity Identity, writeTimeout time.Duration) (*websocket.Conn, sessionAccepted, func(), error) {
	if (state.Status != "Pending" && state.Status != "Managed") || state.EnrollmentID == "" || state.DeviceID == "" || identity.PublicIdentityRef == "" {
		return nil, sessionAccepted{}, func() {}, fmt.Errorf("pending enrollment and identity are required")
	}
	instance, err := validateInstance(state.InstanceURL)
	if err != nil {
		return nil, sessionAccepted{}, func() {}, err
	}
	endpoint, err := websocketURL(state.InstanceURL)
	if err != nil {
		return nil, sessionAccepted{}, func() {}, err
	}
	dialer, err := client.websocketDialer()
	if err != nil {
		return nil, sessionAccepted{}, func() {}, err
	}
	connection, response, err := dialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
		}
		return nil, sessionAccepted{}, func() {}, fmt.Errorf("managed session connection failed")
	}
	connection.SetReadLimit(MaxMessageBytes)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	cleanup := func() {
		select {
		case <-done:
		default:
			close(done)
		}
		_ = connection.Close()
	}
	writeFailure := func(writeErr error) (*websocket.Conn, sessionAccepted, func(), error) {
		cleanup()
		return nil, sessionAccepted{}, func() {}, writeErr
	}
	hello := map[string]any{
		"version": ProtocolVersion, "type": "session.hello", "enrollmentId": state.EnrollmentID,
		"deviceId": state.DeviceID, "publicIdentityRef": identity.PublicIdentityRef,
	}
	if client.PrinterReconcileSupported || client.PrinterStatisticsSupported || client.PrinterJobsSupported || client.PrinterJobCancelSupported || client.PrinterQueueControlSupported || client.IdleScreenSupported || client.RemoteDesktopSupported || client.BrowserSupported {
		capabilities := make([]string, 0, 8)
		if client.PrinterReconcileSupported {
			capabilities = append(capabilities, cupsreconcile.Capability)
		}
		if EffectiveDeviceKind(state.DeviceKind) == DeviceKindPrintServer {
			if client.PrinterReconcileSupported {
				capabilities = append(capabilities, cupsreconcile.CapabilityV2)
			}
		}
		if client.PrinterStatisticsSupported {
			capabilities = append(capabilities, PrinterStatisticsCapability)
		}
		if client.PrinterJobsSupported {
			capabilities = append(capabilities, PrinterJobsCapability)
		}
		if client.PrinterJobCancelSupported {
			capabilities = append(capabilities, PrinterJobCommandCapability)
		}
		if client.PrinterQueueControlSupported {
			capabilities = append(capabilities, PrinterQueueCommandCapability)
			if EffectiveDeviceKind(state.DeviceKind) == DeviceKindKiosk {
				capabilities = append(capabilities, "printer-queue-delete-v1", "printer-usb-add-v1", "printer-default-v1")
			}
		}
		if client.IdleScreenSupported && EffectiveDeviceKind(state.DeviceKind) == DeviceKindKiosk {
			capabilities = append(capabilities, IdleScreenCapability)
		}
		if client.RemoteDesktopSupported && EffectiveDeviceKind(state.DeviceKind) == DeviceKindKiosk {
			capabilities = append(capabilities, RemoteDesktopCapability)
			// Keep the v1 capability during rollout so a server that has not yet
			// learned v2 still delivers the existing desired/ACK exchange.
			capabilities = append(capabilities, RemoteDesktopV2Capability)
		}
		if client.BrowserSupported && EffectiveDeviceKind(state.DeviceKind) == DeviceKindKiosk {
			capabilities = append(capabilities, BrowserCommandCapability)
		}
		hello["capabilities"] = capabilities
	}
	if err := writeSessionMessage(connection, hello, writeTimeout); err != nil {
		return writeFailure(err)
	}
	var challenge sessionChallenge
	if err := readSessionMessage(ctx, connection, &challenge); err != nil {
		cleanup()
		return nil, sessionAccepted{}, func() {}, err
	}
	if err := validateSessionChallenge(challenge, state, identity, instance, client.now()); err != nil {
		cleanup()
		return nil, sessionAccepted{}, func() {}, err
	}
	responseMessage := ChallengeResponse{
		Version: ProtocolVersion, Type: "session.challenge.response", Profile: ProvisionalIdentityProfile,
		SessionID: challenge.SessionID, ChallengeID: challenge.ChallengeID, EnrollmentID: challenge.EnrollmentID,
		IdentityBindingID: challenge.IdentityBindingID, DeviceID: challenge.DeviceID,
		PublicIdentityRef: challenge.PublicIdentityRef, Nonce: challenge.Nonce, Audience: challenge.Audience,
		ExpiresAt: challenge.ExpiresAt,
	}
	responseMessage.Signature, err = encodeIdentitySignature(identity, ChallengeCanonical(responseMessage))
	if err != nil {
		cleanup()
		return nil, sessionAccepted{}, func() {}, err
	}
	if err := writeSessionMessage(connection, responseMessage, writeTimeout); err != nil {
		return writeFailure(err)
	}
	var accepted sessionAccepted
	if err := readSessionMessage(ctx, connection, &accepted); err != nil {
		cleanup()
		return nil, sessionAccepted{}, func() {}, err
	}
	if accepted.Version != ProtocolVersion || accepted.Type != "session.accepted" || accepted.Profile != ProvisionalIdentityProfile || accepted.SessionID != challenge.SessionID || accepted.EnrollmentID != state.EnrollmentID || accepted.DeviceID != state.DeviceID || accepted.IdentityBindingID != challenge.IdentityBindingID {
		cleanup()
		return nil, sessionAccepted{}, func() {}, fmt.Errorf("managed session was not accepted")
	}
	return connection, accepted, cleanup, nil
}

// ConnectAndHeartbeatWithRetry bounds reconnect attempts for a startup smoke check.
func (client Client) ConnectAndHeartbeatWithRetry(ctx context.Context, state State, identity Identity, options SessionOptions, maxAttempts int) (SessionEvidence, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if maxAttempts > 5 {
		maxAttempts = 5
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		evidence, err := client.ConnectAndHeartbeatEvidence(ctx, state, identity, options)
		if err == nil {
			return evidence, nil
		}
		lastErr = err
		if attempt+1 >= maxAttempts {
			break
		}
		timer := time.NewTimer(reconnectDelay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return SessionEvidence{}, fmt.Errorf("managed session reconnect cancelled")
		case <-timer.C:
		}
	}
	return SessionEvidence{}, lastErr
}

func (client Client) ConnectAndHeartbeatEvidence(ctx context.Context, state State, identity Identity, options SessionOptions) (SessionEvidence, error) {
	if options.HeartbeatSequence == 0 {
		options.HeartbeatSequence = 1
	}
	if options.WriteTimeout <= 0 || options.WriteTimeout > 30*time.Second {
		options.WriteTimeout = sessionMessageTimeout
	}
	connection, accepted, cleanup, err := client.openManagedSession(ctx, state, identity, options.WriteTimeout)
	if err != nil {
		return SessionEvidence{}, err
	}
	defer cleanup()
	observedAt := client.now().UTC().Format(time.RFC3339Nano)
	heartbeat := Heartbeat{
		Version: ProtocolVersion, Type: "session.heartbeat", Profile: ProvisionalIdentityProfile,
		SessionID: accepted.SessionID, DeviceID: state.DeviceID, Sequence: options.HeartbeatSequence, ObservedAt: observedAt,
		DisplayMode: client.observeDisplayMode(options.DisplayModeObserver),
	}
	heartbeat.Signature, err = encodeIdentitySignature(identity, HeartbeatCanonical(heartbeat))
	if err != nil {
		return SessionEvidence{}, err
	}
	if err := writeSessionMessage(connection, heartbeat, options.WriteTimeout); err != nil {
		return SessionEvidence{}, err
	}
	var ack heartbeatAccepted
	if err := readSessionMessage(ctx, connection, &ack); err != nil {
		return SessionEvidence{}, err
	}
	if ack.Version != ProtocolVersion || ack.Type != "session.heartbeat.accepted" || ack.SessionID != accepted.SessionID || ack.Sequence != heartbeat.Sequence {
		return SessionEvidence{}, fmt.Errorf("managed session heartbeat was not accepted")
	}
	return SessionEvidence{SessionID: accepted.SessionID, IdentityBindingID: accepted.IdentityBindingID, HeartbeatSequence: heartbeat.Sequence, LastHeartbeatAt: observedAt, DisplayMode: heartbeat.DisplayMode}, nil
}

func encodeIdentitySignature(identity Identity, canonical []byte) (string, error) {
	if len(canonical) == 0 {
		return "", fmt.Errorf("canonical payload is too large")
	}
	return encodeRaw(ed25519.Sign(identity.PrivateKey, canonical)), nil
}

func reconnectDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 5 {
		attempt = 5
	}
	return time.Duration(1<<attempt) * 250 * time.Millisecond
}
