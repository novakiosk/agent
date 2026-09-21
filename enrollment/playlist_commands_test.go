package enrollment

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestPlaylistCommandResetsLiveObservationAndAdvances(t *testing.T) {
	for _, action := range []string{"return-to-assigned", "restart-browser"} {
		for _, failedRotation := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/applied", true: "/failed-rotation"}[failedRotation], func(t *testing.T) {
				fixture, client, _ := newRunFixture(t, false, false)
				fixture.browserCommandAfterSecondAck = browserCommandFixture(action, nil)
				items := []PlaylistItem{{Label: "One", URL: "https://example.test/one", DurationSeconds: 5}, {Label: "Two", URL: "https://example.test/two", DurationSeconds: 5}}
				fixture.desired = DesiredContent{Type: "playlist-v1", GroupID: "group-1", RevisionID: "playlist-1", Revision: 1, Items: items, PayloadHash: PresentationPlaylistPayloadHash(items)}
				ticks := 0
				base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
				client.Now = func() time.Time { ticks++; return base.Add(time.Duration(ticks) * 10 * time.Second) }
				var mu sync.Mutex
				history := []string{}
				factory := func(context.Context, string) (Browser, error) {
					return NewFakeBrowser(func(target string) (string, error) {
						mu.Lock()
						defer mu.Unlock()
						history = append(history, target)
						if failedRotation && len(history) == 2 {
							return "", errors.New("failed rotation")
						}
						return target, nil
					}), nil
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- client.Run(ctx, RunOptions{HeartbeatInterval: 10 * time.Millisecond, ReconnectDelay: time.Millisecond, BrowserFactory: factory})
				}()
				for range 3 {
					select {
					case <-fixture.acks:
					case err := <-done:
						t.Fatalf("Run stopped: %v", err)
					case <-ctx.Done():
						cancel()
						<-done
						persisted, _ := LoadState(client.StateDir)
						mu.Lock()
						got := append([]string(nil), history...)
						mu.Unlock()
						t.Fatalf("timed out awaiting playlist ACK; history=%v state ack=%s cmd=%s error=%s", got, persisted.LastAckResult, persisted.LastBrowserCommandResult, persisted.LastBrowserCommandError)
					}
				}
				cancel()
				<-done
				mu.Lock()
				defer mu.Unlock()
				want := []string{items[0].URL, items[1].URL, items[0].URL, items[1].URL}
				if len(history) < 4 || !reflect.DeepEqual(history[:4], want) {
					t.Fatalf("navigation=%v want prefix%v", history, want)
				}
			})
		}
	}
}
