// Package compose turns one frontend call into several API calls and a merged
// response, all from config. Expressions are CEL, compiled up front so a typo
// fails validate rather than a live request.
package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"bfflash/internal/config"

	"cel.dev/cel-go/cel"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	idRE     = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	interpRE = regexp.MustCompile(`\$\{([^}]+)\}`)
	refRE    = regexp.MustCompile(`\bsteps\s*(?:\.\s*([a-zA-Z_][a-zA-Z0-9_]*)|\[\s*["']([a-zA-Z_][a-zA-Z0-9_]*)["']\s*\])`)
)

// Caller performs a step's GET against the server's own declared APIs.
type Caller func(ctx context.Context, path string) (status int, body []byte, err error)

// StepError is a required step's failure. Status is 0 when no response came back.
type StepError struct {
	ID     string
	Status int
	Err    error
}

func (e *StepError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("step %s: %v", e.ID, e.Err)
	}
	return fmt.Sprintf("step %s: upstream status %d", e.ID, e.Status)
}

func (e *StepError) Unwrap() error { return e.Err }

type part struct {
	literal string
	expr    cel.Program
}

type step struct {
	id       string
	parts    []part
	optional bool
	deps     []string
}

// Plan is a compiled compose entry.
type Plan struct {
	steps   []*step
	respond cel.Program
}

// Compile checks ids, references, cycles and every expression.
func Compile(c config.Compose) (*Plan, error) {
	env, err := cel.NewEnv(cel.Variable("steps", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, s := range c.Steps {
		if !idRE.MatchString(s.ID) {
			return nil, fmt.Errorf("step id %q is not a valid identifier", s.ID)
		}
		if ids[s.ID] {
			return nil, fmt.Errorf("step id %q is used twice", s.ID)
		}
		ids[s.ID] = true
	}

	p := &Plan{}
	for _, s := range c.Steps {
		if !strings.HasPrefix(s.Get, "/") {
			return nil, fmt.Errorf("step %s: get must start with /", s.ID)
		}
		st := &step{id: s.ID, optional: s.Optional}
		for _, ref := range references(s.Get) {
			if !ids[ref] {
				return nil, fmt.Errorf("step %s refers to unknown step %q", s.ID, ref)
			}
			st.deps = append(st.deps, ref)
		}
		if st.parts, err = compileParts(env, s.Get); err != nil {
			return nil, fmt.Errorf("step %s: %w", s.ID, err)
		}
		p.steps = append(p.steps, st)
	}
	if err := p.checkCycles(); err != nil {
		return nil, err
	}
	for _, ref := range references(c.Respond) {
		if !ids[ref] {
			return nil, fmt.Errorf("respond refers to unknown step %q", ref)
		}
	}
	if p.respond, err = compileExpr(env, c.Respond); err != nil {
		return nil, fmt.Errorf("respond: %w", err)
	}
	return p, nil
}

func references(s string) []string {
	var out []string
	for _, m := range refRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1]+m[2])
	}
	return out
}

func compileParts(env *cel.Env, s string) ([]part, error) {
	var parts []part
	last := 0
	for _, m := range interpRE.FindAllStringSubmatchIndex(s, -1) {
		if m[0] > last {
			parts = append(parts, part{literal: s[last:m[0]]})
		}
		prg, err := compileExpr(env, s[m[2]:m[3]])
		if err != nil {
			return nil, err
		}
		parts = append(parts, part{expr: prg})
		last = m[1]
	}
	if last < len(s) {
		parts = append(parts, part{literal: s[last:]})
	}
	return parts, nil
}

func compileExpr(env *cel.Env, src string) (cel.Program, error) {
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(ast)
}

func (p *Plan) checkCycles() error {
	byID := map[string]*step{}
	for _, s := range p.steps {
		byID[s.id] = s
	}
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var visit func(s *step) error
	visit = func(s *step) error {
		switch state[s.id] {
		case visiting:
			return fmt.Errorf("step %s is part of a dependency cycle", s.id)
		case done:
			return nil
		}
		state[s.id] = visiting
		for _, d := range s.deps {
			if err := visit(byID[d]); err != nil {
				return err
			}
		}
		state[s.id] = done
		return nil
	}
	for _, s := range p.steps {
		if err := visit(s); err != nil {
			return err
		}
	}
	return nil
}

// StaticPrefixes lists the fixed leading path of every step, for checking
// against the route table at compile time.
func StaticPrefixes(c config.Compose) []string {
	out := make([]string, len(c.Steps))
	for i, s := range c.Steps {
		p, _, _ := strings.Cut(s.Get, "$")
		p, _, _ = strings.Cut(p, "?")
		out[i] = strings.TrimRight(p, "/")
	}
	return out
}

// Run executes the plan. A step waits only for the steps it references, so
// unrelated steps run in parallel.
func (p *Plan) Run(ctx context.Context, call Caller) ([]byte, error) {
	g, ctx := errgroup.WithContext(ctx)
	done := make(map[string]chan struct{}, len(p.steps))
	for _, s := range p.steps {
		done[s.id] = make(chan struct{})
	}
	var mu sync.Mutex
	results := make(map[string]any, len(p.steps))
	snapshot := func() map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(results)
	}

	for _, s := range p.steps {
		g.Go(func() error {
			defer close(done[s.id])
			for _, d := range s.deps {
				select {
				case <-done[d]:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			res, err := s.run(ctx, snapshot(), call)
			if err != nil {
				if !s.optional {
					return err
				}
				res = map[string]any{"ok": false, "status": int64(failedStatus(err)), "body": nil}
			}
			mu.Lock()
			results[s.id] = res
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	out, _, err := p.respond.Eval(map[string]any{"steps": results})
	if err != nil {
		return nil, fmt.Errorf("respond: %w", err)
	}
	v, err := out.ConvertToNative(reflect.TypeFor[*structpb.Value]())
	if err != nil {
		return nil, fmt.Errorf("respond: %w", err)
	}
	return json.Marshal(v.(*structpb.Value).AsInterface())
}

func failedStatus(err error) int {
	var se *StepError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

func (s *step) run(ctx context.Context, results map[string]any, call Caller) (map[string]any, error) {
	path, err := s.expand(results)
	if err != nil {
		return nil, &StepError{ID: s.id, Err: err}
	}
	status, body, err := call(ctx, path)
	if err != nil {
		return nil, &StepError{ID: s.id, Err: err}
	}
	if status < 200 || status > 299 {
		return nil, &StepError{ID: s.id, Status: status}
	}
	return map[string]any{"ok": true, "status": int64(status), "body": parseBody(body)}, nil
}

func (s *step) expand(results map[string]any) (string, error) {
	var b strings.Builder
	for _, pt := range s.parts {
		if pt.expr == nil {
			b.WriteString(pt.literal)
			continue
		}
		out, _, err := pt.expr.Eval(map[string]any{"steps": results})
		if err != nil {
			return "", err
		}
		text, err := scalar(out.Value())
		if err != nil {
			return "", err
		}
		b.WriteString(escape(text))
	}
	return b.String(), nil
}

func scalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case uint64:
		return strconv.FormatUint(t, 10), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	}
	return "", fmt.Errorf("value of type %T can't go in a URL", v)
}

// escape keeps a value inside its URL component wherever it lands. A value from
// one upstream must never add a path segment or a query parameter to the next.
func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func parseBody(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	return v
}
