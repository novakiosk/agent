package enrollment

import (
	"context"
	"errors"
	"sync"
)

// FakeBrowser records navigation targets and optionally overrides observations.
type FakeBrowser struct {
	Mu      sync.Mutex
	History []string
	Observe func(string) (string, error)
}

func NewFakeBrowser(observe func(string) (string, error)) *FakeBrowser {
	return &FakeBrowser{Observe: observe}
}

func (browser *FakeBrowser) Navigate(_ context.Context, target string) (string, error) {
	if browser == nil {
		return "", errors.New("browser is nil")
	}
	browser.Mu.Lock()
	defer browser.Mu.Unlock()
	browser.History = append(browser.History, target)
	if browser.Observe != nil {
		return browser.Observe(target)
	}
	return target, nil
}

func (browser *FakeBrowser) Reload(ctx context.Context) (string, error) {
	if browser == nil {
		return "", errors.New("browser is nil")
	}
	browser.Mu.Lock()
	target := "about:blank"
	if len(browser.History) > 0 {
		target = browser.History[len(browser.History)-1]
	}
	browser.Mu.Unlock()
	return browser.Navigate(ctx, target)
}

func (browser *FakeBrowser) SetZoom(_ context.Context, percent int) (string, int, error) {
	if browser == nil {
		return "", 0, errors.New("browser is nil")
	}
	if !BrowserZoomAllowlist[percent] {
		return "", 0, errors.New("browser zoom is not allowed")
	}
	browser.Mu.Lock()
	defer browser.Mu.Unlock()
	target := "about:blank"
	if len(browser.History) > 0 {
		target = browser.History[len(browser.History)-1]
	}
	return target, percent, nil
}

func (browser *FakeBrowser) Close() error { return nil }
