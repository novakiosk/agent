package enrollment

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

type idleSurfaceRunner func(context.Context, string, []string, []string) ([]byte, error)

func (run idleSurfaceRunner) Run(ctx context.Context, name string, args, environment []string) ([]byte, error) {
	return run(ctx, name, args, environment)
}

func TestIdleSurfacePreservesPresentationFullscreen(t *testing.T) {
	for _, primaryFullscreen := range []int{0, 1} {
		t.Run(fmt.Sprint(primaryFullscreen), func(t *testing.T) {
			environment := []string{"SWAYSOCK=/run/user/967/sway.sock"}
			calls := 0
			runner := idleSurfaceRunner(func(ctx context.Context, name string, args, env []string) ([]byte, error) {
				calls++
				if name != "/usr/bin/swaymsg" || !slices.Equal(env, environment) {
					t.Fatalf("unexpected command %s %v %v", name, args, env)
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("startup command is not bounded")
				}
				if calls <= 2 {
					if !slices.Equal(args, []string{"-r", "-t", "get_tree"}) {
						t.Fatalf("unexpected tree command %v", args)
					}
					idle := ""
					if calls == 2 {
						idle = `,"floating_nodes":[{"type":"floating_con","id":15,"pid":4240}]`
					}
					return fmt.Appendf(nil, `{"type":"root","nodes":[{"type":"workspace","nodes":[{"type":"con","id":5,"pid":1221,"fullscreen_mode":%d}]%s}]}`, primaryFullscreen, idle), nil
				}
				if calls != 3 || !slices.Equal(args, []string{"-r", "[con_id=15 pid=4240] move scratchpad, fullscreen enable global, focus"}) {
					t.Fatalf("command could change the presentation: %v", args)
				}
				return []byte(`[{"success":true},{"success":true},{"success":true}]`), nil
			})
			if err := showIdleSurface(context.Background(), 4240, environment, runner); err != nil {
				t.Fatal(err)
			}
			if calls != 3 {
				t.Fatalf("calls = %d", calls)
			}
		})
	}
}

func TestIdleSurfaceRejectsInvalidWindowOrSwayReply(t *testing.T) {
	const validTree = `{"type":"root","nodes":[{"type":"con","id":15,"pid":4240}]}`
	for _, test := range []struct {
		name, tree, reply string
		commandErr        error
	}{
		{name: "malformed tree", tree: `{`},
		{name: "missing root", tree: `{}`},
		{name: "ambiguous idle", tree: `{"type":"root","nodes":[{"type":"con","id":15,"pid":4240},{"type":"con","id":16,"pid":4240}]}`},
		{name: "malformed reply", tree: validTree, reply: `{`},
		{name: "empty reply", tree: validTree, reply: `[]`},
		{name: "missing focus reply", tree: validTree, reply: `[{"success":true},{"success":true}]`},
		{name: "scratchpad rejected", tree: validTree, reply: `[{"success":false},{"success":true},{"success":true}]`},
		{name: "fullscreen rejected", tree: validTree, reply: `[{"success":true},{"success":false},{"success":true}]`},
		{name: "focus rejected", tree: validTree, reply: `[{"success":true},{"success":true},{"success":false}]`},
		{name: "command failed", tree: validTree, commandErr: errors.New("sway disconnected")},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			runner := idleSurfaceRunner(func(_ context.Context, _ string, args, _ []string) ([]byte, error) {
				calls++
				if slices.Contains(args, "get_tree") {
					return []byte(test.tree), nil
				}
				if test.tree != validTree {
					t.Fatal("invalid tree caused a window mutation")
				}
				return []byte(test.reply), test.commandErr
			})
			if err := showIdleSurface(context.Background(), 4240, nil, runner); err == nil {
				t.Fatal("invalid Sway state accepted")
			}
			if calls > 2 {
				t.Fatal("Sway failure was retried")
			}
		})
	}
}

func TestIdleSurfaceMapWaitCancelsWithoutChangingAnyWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := idleSurfaceRunner(func(_ context.Context, _ string, args, _ []string) ([]byte, error) {
		if !slices.Contains(args, "get_tree") {
			t.Fatalf("unmapped idle caused a window mutation: %v", args)
		}
		cancel()
		return []byte(`{"type":"root","nodes":[{"type":"con","id":5,"pid":1221}]}`), nil
	})
	if err := showIdleSurface(ctx, 4240, nil, runner); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestIdleSurfaceRejectsInvalidPID(t *testing.T) {
	runner := idleSurfaceRunner(func(context.Context, string, []string, []string) ([]byte, error) {
		t.Fatal("invalid PID reached compositor")
		return nil, nil
	})
	if err := showIdleSurface(context.Background(), 0, nil, runner); err == nil || !strings.Contains(err.Error(), "process") {
		t.Fatalf("error = %v", err)
	}
}
