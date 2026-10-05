package runtimeipc

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/novakiosk/agent/enrollment"
)

type testBrowser struct {
	url    string
	closed bool
}

func (b *testBrowser) Navigate(_ context.Context, url string) (string, error) {
	b.url = url
	return url, nil
}
func (b *testBrowser) Reload(context.Context) (string, error)                { return b.url, nil }
func (b *testBrowser) SetZoom(_ context.Context, z int) (string, int, error) { return b.url, z, nil }
func (b *testBrowser) Close() error                                          { b.closed = true; return nil }
func TestTypedBrowserManagementAndDesiredAuthority(t *testing.T) {
	s, c := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	management := enrollment.RuntimeBrowserManagement{Version: 1, Type: "direct-chromium-v1", Kiosk: true, KioskPrinting: true}
	observed := make(chan enrollment.RuntimeBrowserManagement, 1)
	local := &testBrowser{}
	handler := &Handler{BrowserFactory: func(ctx, lifetime context.Context, m *enrollment.RuntimeBrowserManagement) (enrollment.Browser, error) {
		observed <- *m
		return local, nil
	}}
	stopped := make(chan error, 1)
	go func() { stopped <- serveConnection(ctx, c, uint32(os.Geteuid()), handler) }()
	adapter := &Adapter{Server: s, Origin: "https://control.example"}
	browser, err := adapter.Browser(ctx, &management)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-observed; got != management {
		t.Fatalf("lost browser settings: %+v", got)
	}
	desired := enrollment.DesiredContent{Type: "single-url-v1", GroupID: "group", RevisionID: "revision", Revision: 1, URL: "https://content.example/"}
	desired.PayloadHash = enrollment.PresentationPayloadHash(desired.URL)
	adapter.Snapshot(enrollment.DesiredSnapshot{Desired: &desired})
	if _, err := browser.Navigate(ctx, "https://other.example/"); err == nil {
		t.Fatal("arbitrary target crossed boundary")
	}
	if got, err := browser.Navigate(ctx, desired.URL); err != nil || got != desired.URL {
		t.Fatalf("navigation %q: %v", got, err)
	}
	if err := browser.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("companion failed to stop")
	}
	if !local.closed {
		t.Fatal("browser not cleaned up")
	}
}
func TestNoGenericOrExtraFieldGraphicalOperations(t *testing.T) {
	h := &Handler{}
	for _, kind := range []string{"sign", "exec", "read-file", "private-state", "remote-relay"} {
		if _, err := h.handle(context.Background(), kind, json.RawMessage(`{"bytes":"secret","path":"/private","argv":["sh"]}`)); err == nil {
			t.Fatalf("accepted %s", kind)
		}
	}
	called := false
	h.BrowserFactory = func(context.Context, context.Context, *enrollment.RuntimeBrowserManagement) (enrollment.Browser, error) {
		called = true
		return &testBrowser{}, nil
	}
	body, err := json.Marshal(map[string]any{"generation": randomID(), "management": nil, "argv": []string{"sh"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.handle(context.Background(), "browser.open", body); err == nil || called {
		t.Fatal("extra field reached browser factory")
	}
}

func TestBrowserStartupLeaseDoesNotBecomeChildLifetime(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	operation, expire := context.WithTimeout(lifetime, 10*time.Millisecond)
	defer expire()
	local := &testBrowser{}
	h := &Handler{sessionCtx: lifetime, BrowserFactory: func(startup, child context.Context, _ *enrollment.RuntimeBrowserManagement) (enrollment.Browser, error) {
		if child != lifetime {
			t.Fatal("child lifetime lost")
		}
		<-startup.Done()
		return local, nil
	}}
	body, _ := json.Marshal(browserOpen{Generation: randomID()})
	if _, err := h.handle(operation, "browser.open", body); err == nil {
		t.Fatal("expired startup accepted")
	}
	if !local.closed || h.browser != nil {
		t.Fatal("late startup escaped cleanup")
	}
	if lifetime.Err() != nil {
		t.Fatal("operation expiry killed entire session")
	}
}
