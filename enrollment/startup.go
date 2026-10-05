package enrollment

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var errGraphicalSessionUnavailable = errors.New("graphical session is unavailable")

// WaitForKioskStartup reads only local state until explicit enrollment has
// completed. A lingering user service may start before either enrollment or Sway.
func WaitForKioskStartup(ctx context.Context, stateDir, runtimeMode string) (State, error) {
	return waitForKioskStartup(ctx, stateDir, runtimeMode, time.Second, kioskGraphicalSessionReady)
}

func waitForKioskStartup(ctx context.Context, stateDir, runtimeMode string, interval time.Duration, graphicalReady func() (bool, error)) (State, error) {
	if runtimeMode != "browser" && runtimeMode != "sway" {
		return State{}, fmt.Errorf("runtime mode must be browser or sway")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return State{}, err
		}
		state, err := LoadState(stateDir)
		if err != nil && !errors.Is(err, ErrUnconfigured) {
			return State{}, err
		}
		if err == nil && state.Status == "Managed" {
			if EffectiveDeviceKind(state.DeviceKind) != DeviceKindKiosk {
				return State{}, fmt.Errorf("run is kiosk-only; use novakiosk-agent print-bridge for this managed state")
			}
			if runtimeMode == "browser" {
				return state, nil
			}
			ready, err := graphicalReady()
			if err != nil {
				return State{}, err
			}
			if ready {
				return state, nil
			}
		}
		select {
		case <-ctx.Done():
			return State{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func kioskGraphicalSessionReady() (bool, error) {
	if _, err := browserEnvironment(ChromiumOptions{RequireGraphicalSession: true}); err != nil {
		if errors.Is(err, errGraphicalSessionUnavailable) {
			return false, nil
		}
		return false, err
	}
	_, err := discoverSwaySocket()
	if errors.Is(err, errGraphicalSessionUnavailable) {
		return false, nil
	}
	return err == nil, err
}

// WaitForGraphicalRuntime checks only this account's local Wayland/Sway state.
// The companion never reads the daemon's identity or enrollment directory.
func WaitForGraphicalRuntime(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		ready, err := kioskGraphicalSessionReady()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
