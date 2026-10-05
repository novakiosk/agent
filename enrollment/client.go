package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 64 * 1024

type Client struct {
	StateDir string
	CAPath   string
	Now      func() time.Time
	// DisplayModeObserver is an optional test seam. Production leaves it nil
	// and observes the bounded DRM connector statuses before each heartbeat.
	DisplayModeObserver          func() DisplayMode
	PrinterReconcileSupported    bool
	PrinterStatisticsSupported   bool
	PrinterJobsSupported         bool
	PrinterJobCancelSupported    bool
	PrinterQueueControlSupported bool
	IdleScreenSupported          bool
	RemoteDesktopSupported       bool
	BrowserSupported             bool
	IdleDiagnostics              func(IdleDiagnostic)
	// doer is a narrow package-internal test seam. Production clients leave it nil so the
	// strict system-trust/explicit-CA transport below is always used.
	doer httpDoer
	// rotationCheckpoint injects a stopped process after a durable boundary in tests.
	rotationCheckpoint func(string) error
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

var ErrAlreadyPending = errors.New("pending enrollment already exists")

type EnrollOptions struct {
	InstanceURL       string
	DeviceID          string
	PublicIdentityRef string
	ProofKind         string
	ProofValue        string
	Inventory         Inventory
	RequestedScope    string
	IdempotencyKey    string
	Identity          *Identity
	// EnrollmentCode is held only in memory for the request header. It is
	// never included in Request or persisted pending-attempt/state files.
	EnrollmentCode string
	DeviceKind     DeviceKind
}

func (client Client) now() time.Time {
	if client.Now != nil {
		return client.Now()
	}
	return time.Now().UTC()
}

func (client Client) httpClient() (*http.Client, error) {
	if client.StateDir == "" {
		return nil, fmt.Errorf("state directory is required")
	}
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
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 20 * time.Second,
	}, nil
}

func randomOpaqueValue(prefix string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate enrollment nonce")
	}
	return prefix + hex.EncodeToString(bytes), nil
}

func (client Client) transport() (httpDoer, error) {
	if client.doer != nil {
		return client.doer, nil
	}
	return client.httpClient()
}

func sameAttemptOptions(request Request, options EnrollOptions, instance *url.URL) error {
	if options.IdempotencyKey != "" && options.IdempotencyKey != request.IdempotencyKey {
		return fmt.Errorf("pending enrollment attempt uses a different idempotency key")
	}
	if options.DeviceID != "" && options.DeviceID != request.DeviceID {
		return fmt.Errorf("pending enrollment attempt uses a different device identity")
	}
	if options.RequestedScope != request.RequestedScope {
		return fmt.Errorf("pending enrollment attempt uses a different scope")
	}
	if EffectiveDeviceKind(options.DeviceKind) != EffectiveDeviceKind(request.DeviceKind) {
		return fmt.Errorf("pending enrollment attempt uses a different device kind")
	}
	if request.Audience != instance.String() && request.Audience != strings.TrimRight(instance.String(), "/") {
		return fmt.Errorf("pending enrollment attempt uses a different instance")
	}
	return nil
}

func (client Client) Enroll(ctx context.Context, options EnrollOptions) (State, error) {
	if err := ValidateDeviceKind(options.DeviceKind); err != nil {
		return State{}, fmt.Errorf("invalid device kind: %w", err)
	}
	if err := ValidateScope(options.RequestedScope); err != nil {
		return State{}, fmt.Errorf("invalid enrollment scope: %w", err)
	}
	enrollmentCode := ""
	if options.EnrollmentCode != "" {
		var normalizeErr error
		enrollmentCode, normalizeErr = NormalizeEnrollmentCode(options.EnrollmentCode)
		if normalizeErr != nil {
			return State{}, fmt.Errorf("invalid enrollment code: %w", normalizeErr)
		}
	}
	instance, err := validateInstance(options.InstanceURL)
	if err != nil {
		return State{}, err
	}
	if options.DeviceID != "" {
		if err := ValidateDeviceID(options.DeviceID); err != nil {
			return State{}, fmt.Errorf("invalid device ID: %w", err)
		}
	}
	if options.Identity != nil {
		if err := ValidateDeviceID(options.Identity.DeviceID); err != nil {
			return State{}, fmt.Errorf("invalid local identity device ID: %w", err)
		}
		if options.DeviceID != options.Identity.DeviceID {
			return State{}, fmt.Errorf("enrollment device ID does not match local identity")
		}
	}
	if _, stateErr := LoadState(client.StateDir); stateErr == nil {
		return State{}, ErrAlreadyPending
	} else if !errors.Is(stateErr, ErrUnconfigured) {
		return State{}, stateErr
	}
	now := client.now().UTC()
	request, attemptErr := LoadAttempt(client.StateDir)
	if attemptErr == nil {
		if err := sameAttemptOptions(request, options, instance); err != nil {
			return State{}, err
		}
	} else if !errors.Is(attemptErr, ErrUnconfigured) {
		return State{}, attemptErr
	} else {
		if options.DeviceID == "" || (options.PublicIdentityRef == "" && options.Identity == nil) || (options.ProofValue == "" && options.Identity == nil) {
			return State{}, fmt.Errorf("device identity and proof are required")
		}
		if options.ProofKind == "" && options.Identity == nil {
			return State{}, fmt.Errorf("proof kind is required")
		}
		idempotencyKey := options.IdempotencyKey
		if idempotencyKey == "" {
			idempotencyKey, err = randomOpaqueValue("enroll-")
			if err != nil {
				return State{}, err
			}
		}
		nonce, nonceErr := randomOpaqueValue("nonce-")
		if nonceErr != nil {
			return State{}, nonceErr
		}
		audience := *instance
		audience.RawQuery = ""
		audience.Fragment = ""
		publicIdentityRef := options.PublicIdentityRef
		proofKind := options.ProofKind
		if options.Identity != nil {
			publicIdentityRef = options.Identity.PublicIdentityRef
			proofKind = options.Identity.Profile()
		}
		request = Request{
			Version:           ProtocolVersion,
			Type:              "bootstrap.enrollment",
			IdempotencyKey:    idempotencyKey,
			DeviceID:          options.DeviceID,
			PublicIdentityRef: publicIdentityRef,
			Proof:             Proof{Kind: proofKind, Value: options.ProofValue},
			Inventory:         options.Inventory,
			RequestedScope:    options.RequestedScope,
			Nonce:             nonce,
			Audience:          audience.String(),
			ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			DeviceKind:        EffectiveDeviceKind(options.DeviceKind),
		}
		if options.Identity != nil {
			request.Proof.Value, err = SignEnrollment(*options.Identity, request)
			if err != nil {
				return State{}, err
			}
		}
		if err := SaveAttemptAtomic(client.StateDir, request); err != nil {
			return State{}, err
		}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return State{}, fmt.Errorf("encode enrollment request")
	}
	httpClient, err := client.transport()
	if err != nil {
		return State{}, err
	}
	endpoint := strings.TrimRight(instance.String(), "/") + "/v1/enrollments"
	requestURL, err := url.Parse(endpoint)
	if err != nil || requestURL.Scheme != "https" {
		return State{}, fmt.Errorf("enrollment endpoint must use HTTPS")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), strings.NewReader(string(payload)))
	if err != nil {
		return State{}, fmt.Errorf("create enrollment request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	if enrollmentCode != "" {
		httpRequest.Header.Set("Nova-Enrollment-Code", enrollmentCode)
	}
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return State{}, fmt.Errorf("enrollment transport failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return State{}, fmt.Errorf("read enrollment response")
	}
	if len(data) > maxResponseBytes {
		return State{}, fmt.Errorf("enrollment response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return State{}, fmt.Errorf("enrollment rejected with HTTP status %d", response.StatusCode)
	}
	result, err := decodeResult(data, request, now)
	if err != nil {
		return State{}, err
	}
	state := State{
		Version:           ProtocolVersion,
		Status:            "Pending",
		InstanceURL:       instance.String(),
		EnrollmentID:      result.EnrollmentID,
		DeviceID:          result.DeviceID,
		ComparisonValue:   result.ComparisonValue,
		ExpiresAt:         result.ExpiresAt,
		PublicIdentityRef: request.PublicIdentityRef,
		DeviceKind:        EffectiveDeviceKind(request.DeviceKind),
	}
	if err := SaveStateAtomic(client.StateDir, state); err != nil {
		return State{}, err
	}
	if err := ClearAttempt(client.StateDir); err != nil {
		return State{}, err
	}
	return state, nil
}

func (client Client) Claim(ctx context.Context, state State, identity Identity) (IdentityClaimResult, error) {
	instance, err := validateInstance(state.InstanceURL)
	if err != nil {
		return IdentityClaimResult{}, err
	}
	if state.EnrollmentID == "" || state.DeviceID == "" || identity.PublicIdentityRef == "" {
		return IdentityClaimResult{}, fmt.Errorf("pending enrollment and identity are required")
	}
	nonce, err := randomOpaqueValue("claim-")
	if err != nil {
		return IdentityClaimResult{}, err
	}
	claim := IdentityClaim{
		Version: ProtocolVersion, Type: "bootstrap.identity.claim", EnrollmentID: state.EnrollmentID,
		DeviceID: state.DeviceID, PublicIdentityRef: identity.PublicIdentityRef, Nonce: nonce,
		Audience: instance.String(), ExpiresAt: client.now().UTC().Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
	claim.Signature, err = SignClaim(identity, claim)
	if err != nil {
		return IdentityClaimResult{}, err
	}
	payload, err := json.Marshal(claim)
	if err != nil {
		return IdentityClaimResult{}, fmt.Errorf("encode identity claim")
	}
	doer, err := client.transport()
	if err != nil {
		return IdentityClaimResult{}, err
	}
	endpoint := strings.TrimRight(instance.String(), "/") + "/v1/enrollments/" + url.PathEscape(state.EnrollmentID) + "/claim"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return IdentityClaimResult{}, fmt.Errorf("create identity claim request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := doer.Do(httpRequest)
	if err != nil {
		return IdentityClaimResult{}, fmt.Errorf("identity claim transport failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return IdentityClaimResult{}, fmt.Errorf("identity claim response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return IdentityClaimResult{}, fmt.Errorf("identity claim rejected with HTTP status %d", response.StatusCode)
	}
	var result IdentityClaimResult
	if err := decodeStrict(data, &result); err != nil {
		return IdentityClaimResult{}, err
	}
	if result.Version != ProtocolVersion || result.Type != "bootstrap.identity.claim.result" || (result.Status != "pending" && result.Status != "approved") || result.EnrollmentID != state.EnrollmentID || result.DeviceID != state.DeviceID {
		return IdentityClaimResult{}, fmt.Errorf("identity claim response is invalid")
	}
	if result.Status == "pending" && (result.IdentityState != "unbound" || result.IdentityBindingID != nil || result.SessionPath != nil) {
		return IdentityClaimResult{}, fmt.Errorf("pending identity claim response is invalid")
	}
	if result.Status == "approved" && (result.IdentityState != "bound" || result.IdentityBindingID == nil || *result.IdentityBindingID == "" || result.SessionPath == nil || *result.SessionPath != SessionPath) {
		return IdentityClaimResult{}, fmt.Errorf("approved identity claim response is invalid")
	}
	return result, nil
}

func Status(stateDir string) (string, State, error) {
	state, err := LoadState(stateDir)
	if errors.Is(err, ErrUnconfigured) {
		return "Unconfigured", State{}, nil
	}
	if err != nil {
		return "Error", State{}, err
	}
	return state.Status, state, nil
}
