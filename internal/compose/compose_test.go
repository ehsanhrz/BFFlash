package compose

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfflash/internal/config"
)

func plan(t *testing.T, respond string, steps ...config.Step) *Plan {
	t.Helper()
	p, err := Compile(config.Compose{Steps: steps, Respond: respond})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDependentStepsAndRespond(t *testing.T) {
	p := plan(t, `{"name": steps.me.body.name, "orders": steps.orders.body}`,
		config.Step{ID: "me", Get: "/users/me"},
		config.Step{ID: "orders", Get: "/orders?user=${steps.me.body.id}"},
	)
	var seen sync.Map
	out, err := p.Run(context.Background(), func(_ context.Context, path string) (int, []byte, error) {
		seen.Store(path, true)
		if path == "/users/me" {
			return 200, []byte(`{"id":42,"name":"Alice"}`), nil
		}
		return 200, []byte(`[1,2]`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := seen.Load("/orders?user=42"); !ok {
		t.Error("orders step did not get the id from me")
	}
	var got map[string]any
	json.Unmarshal(out, &got)
	if got["name"] != "Alice" || len(got["orders"].([]any)) != 2 {
		t.Errorf("out = %s", out)
	}
}

func TestUnrelatedStepsRunInParallel(t *testing.T) {
	p := plan(t, `{}`, config.Step{ID: "a", Get: "/a"}, config.Step{ID: "b", Get: "/b"})
	var running, peak atomic.Int32
	_, err := p.Run(context.Background(), func(context.Context, string) (int, []byte, error) {
		n := running.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		time.Sleep(30 * time.Millisecond)
		running.Add(-1)
		return 200, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 2 {
		t.Errorf("peak concurrency = %d", peak.Load())
	}
}

func TestOptionalFailureIsVisibleNotFatal(t *testing.T) {
	p := plan(t, `{"ok": steps.b.ok, "status": steps.b.status, "b": steps.b.body, "a": steps.a.body}`,
		config.Step{ID: "a", Get: "/a"},
		config.Step{ID: "b", Get: "/b", Optional: true},
	)
	out, err := p.Run(context.Background(), func(_ context.Context, path string) (int, []byte, error) {
		if path == "/b" {
			return 503, nil, nil
		}
		return 200, []byte(`"fine"`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":"fine","b":null,"ok":false,"status":503}` {
		t.Errorf("out = %s", out)
	}
}

func TestRequiredFailureFailsAndCarriesStatus(t *testing.T) {
	p := plan(t, `{}`, config.Step{ID: "a", Get: "/a"})
	_, err := p.Run(context.Background(), func(context.Context, string) (int, []byte, error) {
		return 401, nil, nil
	})
	var se *StepError
	if !errors.As(err, &se) || se.ID != "a" || se.Status != 401 {
		t.Fatalf("err = %v", err)
	}
}

func TestOptionalStepDependingOnFailedOptional(t *testing.T) {
	p := plan(t, `{"b": steps.b.ok}`,
		config.Step{ID: "a", Get: "/a", Optional: true},
		config.Step{ID: "b", Get: "/b/${steps.a.body.id}", Optional: true},
	)
	out, err := p.Run(context.Background(), func(context.Context, string) (int, []byte, error) {
		return 500, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"b":false}` {
		t.Errorf("out = %s", out)
	}
}

func TestValuesCannotEscapeTheirComponent(t *testing.T) {
	p := plan(t, `{}`,
		config.Step{ID: "a", Get: "/a"},
		config.Step{ID: "b", Get: "/b/${steps.a.body.v}?x=${steps.a.body.v}"},
	)
	var got atomic.Value
	_, err := p.Run(context.Background(), func(_ context.Context, path string) (int, []byte, error) {
		if path == "/a" {
			return 200, []byte(`{"v":"../admin?y=1&z=2 3"}`), nil
		}
		got.Store(path)
		return 200, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "/b/..%2Fadmin%3Fy%3D1%26z%3D2%203?x=..%2Fadmin%3Fy%3D1%26z%3D2%203"
	if got.Load() != want {
		t.Errorf("path = %s", got.Load())
	}
}

func TestObjectValueInURLIsAnError(t *testing.T) {
	p := plan(t, `{}`,
		config.Step{ID: "a", Get: "/a"},
		config.Step{ID: "b", Get: "/b/${steps.a.body}"},
	)
	_, err := p.Run(context.Background(), func(context.Context, string) (int, []byte, error) {
		return 200, []byte(`{"v":1}`), nil
	})
	if err == nil {
		t.Fatal("want an error")
	}
}

func TestLargeNumbersStayIntact(t *testing.T) {
	p := plan(t, `{}`,
		config.Step{ID: "a", Get: "/a"},
		config.Step{ID: "b", Get: "/b/${steps.a.body.v}"},
	)
	var got atomic.Value
	p.Run(context.Background(), func(_ context.Context, path string) (int, []byte, error) {
		if path == "/a" {
			return 200, []byte(`{"v":10000000}`), nil
		}
		got.Store(path)
		return 200, nil, nil
	})
	if got.Load() != "/b/10000000" {
		t.Errorf("path = %v", got.Load())
	}
}

func TestCompileRejects(t *testing.T) {
	cases := []struct {
		name    string
		respond string
		steps   []config.Step
		want    string
	}{
		{"bad id", `{}`, []config.Step{{ID: "a-b", Get: "/a"}}, "identifier"},
		{"duplicate id", `{}`, []config.Step{{ID: "a", Get: "/a"}, {ID: "a", Get: "/b"}}, "twice"},
		{"relative get", `{}`, []config.Step{{ID: "a", Get: "a"}}, "start with /"},
		{"unknown ref", `{}`, []config.Step{{ID: "a", Get: "/a/${steps.nope.x}"}}, "unknown step"},
		{"unknown ref in respond", `{"x": steps.nope}`, []config.Step{{ID: "a", Get: "/a"}}, "unknown step"},
		{"self cycle", `{}`, []config.Step{{ID: "a", Get: "/a/${steps.a.x}"}}, "cycle"},
		{"long cycle", `{}`, []config.Step{{ID: "a", Get: "/a/${steps.b.x}"}, {ID: "b", Get: "/b/${steps.a.x}"}}, "cycle"},
		{"bad expression", `{`, []config.Step{{ID: "a", Get: "/a"}}, "respond"},
		{"bad interpolation", `{}`, []config.Step{{ID: "a", Get: "/a/${1 +}"}}, "step a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compile(config.Compose{Steps: c.steps, Respond: c.respond})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
