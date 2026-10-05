package runtimeipc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/novakiosk/agent/cupsreconcile"
	"github.com/novakiosk/agent/enrollment"
)

type empty struct{}
type browserOpen struct {
	Generation string                               `json:"generation"`
	Management *enrollment.RuntimeBrowserManagement `json:"management"`
}
type browserID struct {
	Generation string `json:"generation"`
}
type browserNavigate struct {
	Generation string                    `json:"generation"`
	Desired    enrollment.DesiredContent `json:"desired"`
	Target     string                    `json:"target"`
}
type browserAction struct {
	Generation string                    `json:"generation"`
	Command    enrollment.BrowserCommand `json:"command"`
}
type browserObservation struct {
	URL  string `json:"url"`
	Zoom int    `json:"zoom"`
}
type aliveObservation struct {
	Alive bool `json:"alive"`
}
type idleApply struct {
	Origin  string                  `json:"origin"`
	Desired *enrollment.IdleDesired `json:"desired"`
}

// Handler dependencies are local configuration, never supplied by the socket.
// In particular paths, binaries, environment and privileged helpers are absent.
type Handler struct {
	BrowserFactory    func(context.Context, context.Context, *enrollment.RuntimeBrowserManagement) (enrollment.Browser, error)
	Runtime           enrollment.RuntimeApplier
	IdleFactory       func(context.Context, string) (enrollment.IdleRuntime, error)
	Default           cupsreconcile.Reconciler
	WayVNC            func(context.Context, enrollment.WayVNCSession) (enrollment.RemoteDesktopProcess, error)
	sessionCtx        context.Context
	browser           enrollment.Browser
	browserGeneration string
	idle              enrollment.IdleRuntime
	origin            string
	remote            enrollment.RemoteDesktopProcess
	remoteSession     string
}

func stopRemote(process enrollment.RemoteDesktopProcess) {
	process.Terminate()
	done := make(chan struct{})
	go func() { process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		process.Kill()
	}
}

func (handler *Handler) close() {
	if handler.browser != nil {
		handler.browser.Close()
		handler.browser = nil
	}
	if handler.idle != nil {
		handler.idle.Close()
		handler.idle = nil
	}
	if handler.remote != nil {
		stopRemote(handler.remote)
		handler.remote = nil
	}
	handler.browserGeneration = ""
	handler.remoteSession = ""
	handler.origin = ""
}
func validObservedURL(value string) bool {
	if value == "about:blank" {
		return true
	}
	normalized, err := enrollment.CanonicalPresentationURL(value)
	return err == nil && normalized == value && len(value) <= 2048
}
func validDesiredTarget(desired enrollment.DesiredContent, target string) bool {
	if desired.GroupID == "" || desired.RevisionID == "" || desired.Revision == 0 || len(desired.RevisionID) > 128 || len(desired.GroupID) > 128 {
		return false
	}
	normalized, err := enrollment.CanonicalPresentationURL(target)
	if err != nil || normalized != target {
		return false
	}
	if desired.Type == "single-url-v1" {
		return desired.URL == target && desired.PayloadHash == enrollment.PresentationPayloadHash(desired.URL)
	}
	if desired.Type != "playlist-v1" || len(desired.Items) < 1 || len(desired.Items) > 100 || desired.PayloadHash != enrollment.PresentationPlaylistPayloadHash(desired.Items) {
		return false
	}
	for _, item := range desired.Items {
		if item.URL == target {
			return true
		}
	}
	return false
}
func (handler *Handler) handle(ctx context.Context, kind string, body json.RawMessage) (any, error) {
	switch kind {
	case "browser.open":
		var input browserOpen
		if strict(body, &input) != nil || len(input.Generation) != 64 || handler.BrowserFactory == nil {
			return nil, ErrUnavailable
		}
		if input.Management != nil && (input.Management.Version != 1 || input.Management.Type != "direct-chromium-v1") {
			return nil, ErrUnavailable
		}
		if handler.browser != nil {
			handler.browser.Close()
			handler.browser = nil
		}
		browser, err := handler.BrowserFactory(ctx, handler.sessionCtx, input.Management)
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			browser.Close()
			return nil, ctx.Err()
		}
		handler.browser = browser
		handler.browserGeneration = input.Generation
		return empty{}, nil
	case "browser.navigate":
		var input browserNavigate
		if strict(body, &input) != nil || input.Generation != handler.browserGeneration || handler.browser == nil || !validDesiredTarget(input.Desired, input.Target) {
			return nil, ErrUnavailable
		}
		observed, err := handler.browser.Navigate(ctx, input.Target)
		if err != nil || !validObservedURL(observed) {
			return nil, ErrUnavailable
		}
		return browserObservation{URL: observed}, nil
	case "browser.reload", "browser.zoom":
		var input browserAction
		if strict(body, &input) != nil || input.Generation != handler.browserGeneration || handler.browser == nil || input.Command.Validate(time.Now(), false) != nil {
			return nil, ErrUnavailable
		}
		var observed string
		var zoom int
		var err error
		if kind == "browser.reload" && input.Command.Action == "reload" {
			observed, err = handler.browser.Reload(ctx)
		} else if kind == "browser.zoom" && input.Command.Action == "set-zoom" && input.Command.ZoomPercent != nil {
			observed, zoom, err = handler.browser.SetZoom(ctx, *input.Command.ZoomPercent)
		} else {
			return nil, ErrUnavailable
		}
		if err != nil || !validObservedURL(observed) {
			return nil, ErrUnavailable
		}
		return browserObservation{URL: observed, Zoom: zoom}, nil
	case "browser.close", "browser.status":
		var input browserID
		if strict(body, &input) != nil || input.Generation != handler.browserGeneration {
			return nil, ErrUnavailable
		}
		if kind == "browser.close" {
			if handler.browser != nil {
				handler.browser.Close()
				handler.browser = nil
			}
			return empty{}, nil
		}
		alive := handler.browser != nil
		if owned, ok := handler.browser.(interface{ Done() <-chan struct{} }); ok {
			select {
			case <-owned.Done():
				alive = false
			default:
			}
		}
		return aliveObservation{Alive: alive}, nil
	case "runtime.recover":
		var input empty
		if strict(body, &input) != nil || handler.Runtime == nil {
			return nil, ErrUnavailable
		}
		return empty{}, handler.Runtime.Recover(ctx)
	case "runtime.apply":
		var input enrollment.RuntimeArtifact
		if strict(body, &input) != nil || enrollment.ValidateRuntimeArtifact(input) != nil || handler.Runtime == nil {
			return nil, ErrUnavailable
		}
		return empty{}, handler.Runtime.Apply(ctx, input)
	case "idle.apply":
		var input idleApply
		if strict(body, &input) != nil || handler.IdleFactory == nil {
			return nil, ErrUnavailable
		}
		origin, err := enrollment.CanonicalInstanceURL(input.Origin)
		if err != nil || origin != input.Origin || (handler.origin != "" && handler.origin != origin) {
			return nil, ErrUnavailable
		}
		if input.Desired != nil && enrollment.ValidateIdleDesired(*input.Desired) != nil {
			return nil, ErrUnavailable
		}
		if handler.idle == nil {
			handler.idle, err = handler.IdleFactory(handler.sessionCtx, origin)
			if err != nil {
				return nil, err
			}
			handler.origin = origin
		}
		return empty{}, handler.idle.Apply(ctx, input.Desired)
	case "idle.close":
		var input empty
		if strict(body, &input) != nil {
			return nil, ErrUnavailable
		}
		if handler.idle != nil {
			err := handler.idle.Close()
			handler.idle = nil
			return empty{}, err
		}
		return empty{}, nil
	case "printer.default":
		var input cupsreconcile.Desired
		if strict(body, &input) != nil || input.Validate() != nil {
			return nil, ErrUnavailable
		}
		return empty{}, handler.Default.MaintainDefault(ctx, input)
	case "wayvnc.start":
		var input enrollment.WayVNCSession
		if strict(body, &input) != nil || handler.WayVNC == nil {
			return nil, ErrUnavailable
		}
		if handler.remote != nil {
			stopRemote(handler.remote)
			handler.remote = nil
		}
		process, err := handler.WayVNC(handler.sessionCtx, input)
		if err != nil {
			return nil, err
		}
		handler.remote = process
		handler.remoteSession = input.SessionID
		return empty{}, nil
	case "wayvnc.stop", "wayvnc.status":
		var input struct {
			SessionID string `json:"sessionId"`
		}
		if strict(body, &input) != nil || input.SessionID != handler.remoteSession {
			return nil, ErrUnavailable
		}
		if kind == "wayvnc.status" {
			return aliveObservation{Alive: handler.remote != nil && handler.remote.Alive()}, nil
		}
		if handler.remote != nil {
			stopRemote(handler.remote)
			handler.remote = nil
		}
		return empty{}, nil
	}
	return nil, errors.New("unsupported graphical operation")
}

type Adapter struct {
	Server  *Server
	Origin  string
	mu      sync.Mutex
	desired *enrollment.DesiredContent
	command *enrollment.BrowserCommand
}

func (adapter *Adapter) Snapshot(snapshot enrollment.DesiredSnapshot) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.desired = snapshot.Desired
	adapter.command = snapshot.BrowserCommand
}
func (adapter *Adapter) Recover(ctx context.Context) error { return nil }
func (adapter *Adapter) Epoch() string {
	p := adapter.Server.currentPeer()
	if p == nil {
		return ""
	}
	select {
	case <-p.done:
		return ""
	default:
		return p.epoch
	}
}
func (adapter *Adapter) Apply(ctx context.Context, artifact enrollment.RuntimeArtifact) error {
	return adapter.Server.call(ctx, adapter.Server.currentPeer(), "runtime.apply", artifact, &empty{})
}
func (adapter *Adapter) Browser(ctx context.Context, management *enrollment.RuntimeBrowserManagement) (enrollment.Browser, error) {
	p := adapter.Server.currentPeer()
	generation := randomID()
	if err := adapter.Server.call(ctx, p, "browser.open", browserOpen{Generation: generation, Management: management}, &empty{}); err != nil {
		return nil, err
	}
	browser := &remoteBrowser{adapter: adapter, peer: p, generation: generation, done: make(chan struct{})}
	go browser.watch()
	return browser, nil
}
func (adapter *Adapter) Idle() enrollment.IdleRuntime { return &remoteIdle{adapter: adapter} }
func (adapter *Adapter) MaintainDefault(ctx context.Context, desired cupsreconcile.Desired) error {
	return adapter.Server.call(ctx, adapter.Server.currentPeer(), "printer.default", desired, &empty{})
}

type Reconciler struct {
	cupsreconcile.Reconciler
	Adapter *Adapter
}

func (r Reconciler) MaintainDefault(ctx context.Context, desired cupsreconcile.Desired) error {
	return r.Adapter.MaintainDefault(ctx, desired)
}

type remoteBrowser struct {
	adapter    *Adapter
	peer       *peer
	generation string
	done       chan struct{}
	once       sync.Once
}

func (browser *remoteBrowser) Done() <-chan struct{} { return browser.done }
func (browser *remoteBrowser) ended()                { browser.once.Do(func() { close(browser.done) }) }
func (browser *remoteBrowser) watch() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-browser.done:
			return
		case <-browser.peer.done:
			browser.ended()
			return
		case <-ticker.C:
			var result aliveObservation
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := browser.adapter.Server.call(ctx, browser.peer, "browser.status", browserID{Generation: browser.generation}, &result)
			cancel()
			if err != nil || !result.Alive {
				browser.ended()
				return
			}
		}
	}
}
func (browser *remoteBrowser) Navigate(ctx context.Context, target string) (string, error) {
	browser.adapter.mu.Lock()
	desired := browser.adapter.desired
	browser.adapter.mu.Unlock()
	if desired == nil || !validDesiredTarget(*desired, target) {
		return "", ErrUnavailable
	}
	var result browserObservation
	err := browser.adapter.Server.call(ctx, browser.peer, "browser.navigate", browserNavigate{Generation: browser.generation, Desired: *desired, Target: target}, &result)
	if err != nil || !validObservedURL(result.URL) || result.Zoom != 0 {
		return "", ErrUnavailable
	}
	return result.URL, nil
}
func (browser *remoteBrowser) action(ctx context.Context, kind string, zoom int) (string, int, error) {
	browser.adapter.mu.Lock()
	command := browser.adapter.command
	browser.adapter.mu.Unlock()
	if command == nil {
		return "", 0, ErrUnavailable
	}
	if kind == "browser.zoom" && (command.ZoomPercent == nil || *command.ZoomPercent != zoom) {
		return "", 0, ErrUnavailable
	}
	var result browserObservation
	err := browser.adapter.Server.call(ctx, browser.peer, kind, browserAction{Generation: browser.generation, Command: *command}, &result)
	if err != nil || !validObservedURL(result.URL) || (kind == "browser.zoom" && result.Zoom != zoom) || (kind == "browser.reload" && result.Zoom != 0) {
		return "", 0, ErrUnavailable
	}
	return result.URL, result.Zoom, nil
}
func (browser *remoteBrowser) Reload(ctx context.Context) (string, error) {
	value, _, err := browser.action(ctx, "browser.reload", 0)
	return value, err
}
func (browser *remoteBrowser) SetZoom(ctx context.Context, percent int) (string, int, error) {
	return browser.action(ctx, "browser.zoom", percent)
}
func (browser *remoteBrowser) Close() error {
	browser.ended()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return browser.adapter.Server.call(ctx, browser.peer, "browser.close", browserID{Generation: browser.generation}, &empty{})
}

type remoteIdle struct{ adapter *Adapter }

func (idle *remoteIdle) Apply(ctx context.Context, desired *enrollment.IdleDesired) error {
	return idle.adapter.Server.call(ctx, idle.adapter.Server.currentPeer(), "idle.apply", idleApply{Origin: idle.adapter.Origin, Desired: desired}, &empty{})
}
func (idle *remoteIdle) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return idle.adapter.Server.call(ctx, idle.adapter.Server.currentPeer(), "idle.close", empty{}, &empty{})
}

func (adapter *Adapter) StartWayVNC(ctx context.Context, session enrollment.WayVNCSession) (enrollment.RemoteDesktopProcess, error) {
	if session.Validate(time.Now()) != nil {
		return nil, ErrUnavailable
	}
	p := adapter.Server.currentPeer()
	if err := adapter.Server.call(ctx, p, "wayvnc.start", session, &empty{}); err != nil {
		return nil, err
	}
	process := &remoteProcess{adapter: adapter, peer: p, sessionID: session.SessionID, done: make(chan struct{})}
	go process.watch()
	return process, nil
}

type remoteProcess struct {
	adapter   *Adapter
	peer      *peer
	sessionID string
	done      chan struct{}
	once      sync.Once
}

func (process *remoteProcess) ended() { process.once.Do(func() { close(process.done) }) }
func (process *remoteProcess) Alive() bool {
	select {
	case <-process.done:
		return false
	default:
		return true
	}
}
func (process *remoteProcess) Wait() error { <-process.done; return nil }
func (process *remoteProcess) watch() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-process.done:
			return
		case <-process.peer.done:
			process.ended()
			return
		case <-ticker.C:
			var result aliveObservation
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := process.adapter.Server.call(ctx, process.peer, "wayvnc.status", struct {
				SessionID string `json:"sessionId"`
			}{process.sessionID}, &result)
			cancel()
			if err != nil || !result.Alive {
				process.ended()
				return
			}
		}
	}
}
func (process *remoteProcess) Terminate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := process.adapter.Server.call(ctx, process.peer, "wayvnc.stop", struct {
		SessionID string `json:"sessionId"`
	}{process.sessionID}, &empty{})
	process.ended()
	return err
}
func (process *remoteProcess) Kill() error { return process.Terminate() }
