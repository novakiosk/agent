package enrollment

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// WayVNCSession is the only remote-desktop material exposed to the graphical
// companion. It deliberately excludes the device relay token and instance URL.
type WayVNCSession struct {
	SessionID string `json:"sessionId"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expiresAt"`
}

func (session WayVNCSession) Validate(now time.Time) error {
	expires, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if err != nil || !validRemoteDesktopID(session.SessionID) || !remoteDesktopUsername(session.Username) || !remoteDesktopToken(session.Password) || !expires.After(now) || expires.After(now.Add(30*time.Minute)) {
		return fmt.Errorf("invalid WayVNC session")
	}
	return nil
}

// StartWayVNC owns only a fixed WayVNC child/config, never the authenticated relay.
func StartWayVNC(ctx context.Context, options RemoteDesktopManagerOptions, session WayVNCSession) (RemoteDesktopProcess, error) {
	if err := session.Validate(time.Now()); err != nil {
		return nil, err
	}
	// This manager supplies existing private config/environment validation only.
	options.LocalStart = nil
	manager, err := NewRemoteDesktopManager(options)
	if err != nil {
		return nil, err
	}
	environment := manager.graphicalEnvironment()
	if len(environment) == 0 {
		return nil, fmt.Errorf("graphical-session-unavailable")
	}
	desired := RemoteDesktopDesired{SessionID: session.SessionID, WayVNCUsername: session.Username, WayVNCPassword: session.Password}
	config, err := manager.writeConfig(&desired)
	if err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithDeadline(ctx, timeFromString(session.ExpiresAt))
	child, err := manager.options.Runner.Start(childCtx, manager.options.WayVNCBinary, []string{"--config", config}, environment)
	if err != nil {
		cancel()
		removeRemoteDesktopConfig(config)
		return nil, err
	}
	process := &wayVNCProcess{RemoteDesktopProcess: child, cancel: cancel, config: config, done: make(chan struct{})}
	go func() { process.err = child.Wait(); process.cleanup(); close(process.done) }()
	return process, nil
}

type wayVNCProcess struct {
	RemoteDesktopProcess
	cancel context.CancelFunc
	config string
	done   chan struct{}
	once   sync.Once
	err    error
}

func (process *wayVNCProcess) cleanup() {
	process.once.Do(func() { process.cancel(); removeRemoteDesktopConfig(process.config) })
}
func (process *wayVNCProcess) Wait() error { <-process.done; return process.err }
