// Package server compiles a config into the running handler.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"

	"bfflash/internal/auth"
	"bfflash/internal/cache"
	"bfflash/internal/compose"
	"bfflash/internal/config"
	"bfflash/internal/limit"
	"bfflash/internal/match"
	"bfflash/internal/observe"
	"bfflash/internal/proxy"
	"bfflash/internal/session"
)

// Deps is the state that survives a config reload.
type Deps struct {
	Log     *slog.Logger
	Store   session.Store
	Sealer  *session.Sealer
	Limiter *limit.Limiter
	Cache   *cache.Cache
	Forward *proxy.Forwarder
	// HTTP overrides the client used to reach the identity provider.
	HTTP *http.Client
}

// NewDeps builds the long-lived state a config asks for.
func NewDeps(cfg *config.Config, log *slog.Logger) (*Deps, error) {
	sealer, err := session.NewSealer(cfg.Session.EncryptionKey)
	if err != nil {
		return nil, err
	}
	d := &Deps{
		Log:     log,
		Sealer:  sealer,
		Limiter: limit.New(),
		Cache:   cache.New(),
		Forward: proxy.New(log, nil),
	}
	if cfg.Session.Store == "redis" {
		if d.Store, err = session.NewRedis(cfg.Session.URL, sealer); err != nil {
			return nil, err
		}
	} else {
		d.Store = session.NewMemory(sealer)
	}
	return d, nil
}

type rule struct {
	pattern match.Pattern
	policy  config.Effective
}

type route struct {
	path    string
	targets map[string]*url.URL // keyed by service name, "" for a plain API
	policy  config.Effective
	rules   []rule
	plan    *compose.Plan
}

// policyFor returns the first matching rule's policy, or the route's own, with
// a scope that keeps rate buckets of different rules apart.
func (rt *route) policyFor(method, rest string) (config.Effective, string) {
	for i := range rt.rules {
		if rt.rules[i].pattern.Match(method, rest) {
			return rt.rules[i].policy, fmt.Sprintf("%s#%d", rt.path, i)
		}
	}
	return rt.policy, rt.path
}

// Handler is one compiled config. It is immutable, so a reload swaps it whole.
type Handler struct {
	cfg      *config.Config
	deps     *Deps
	auth     *auth.Service
	table    *match.Table[*route]
	frontend http.Handler
}

// Compile turns a validated config into a Handler. It makes no network calls,
// so validate can use it offline.
func Compile(cfg *config.Config, deps *Deps) (*Handler, error) {
	h := &Handler{cfg: cfg, deps: deps}
	base := config.Builtin().Apply(cfg.Defaults)

	var entries []match.Entry[*route]
	for i := range cfg.APIs {
		a := &cfg.APIs[i]
		rt := &route{path: a.Path, policy: base.Apply(a.Policy), targets: map[string]*url.URL{}}
		for _, r := range a.Rules {
			method, pattern, err := config.ParseMatch(r.Match)
			if err != nil {
				return nil, err
			}
			rt.rules = append(rt.rules, rule{match.NewPattern(method, pattern), rt.policy.Apply(r.Policy)})
		}
		e := match.Entry[*route]{Prefix: a.Path, Value: rt}
		if len(a.Allow) > 0 {
			i := strings.LastIndex(a.Path, "/")
			placeholder := a.Path[i+1:]
			e.Prefix, e.Var, e.Allow = a.Path[:i], true, map[string]bool{}
			if e.Prefix == "" {
				e.Prefix = "/"
			}
			for _, name := range a.Allow {
				u, err := url.Parse(strings.ReplaceAll(a.To, placeholder, name))
				if err != nil {
					return nil, fmt.Errorf("apis %s: %w", a.Path, err)
				}
				rt.targets[name] = u
				e.Allow[name] = true
			}
		} else {
			u, err := url.Parse(a.To)
			if err != nil {
				return nil, fmt.Errorf("apis %s: %w", a.Path, err)
			}
			rt.targets[""] = u
		}
		entries = append(entries, e)
	}
	for _, c := range cfg.Compose {
		plan, err := compose.Compile(c)
		if err != nil {
			return nil, fmt.Errorf("compose %s: %w", c.Path, err)
		}
		rt := &route{path: c.Path, policy: base.Apply(c.Policy), plan: plan}
		entries = append(entries, match.Entry[*route]{Prefix: c.Path, Exact: true, Value: rt})
	}
	h.table = match.NewTable(entries)

	for _, c := range cfg.Compose {
		for _, prefix := range compose.StaticPrefixes(c) {
			res := h.table.Lookup(prefix)
			if !res.Found || res.Value.plan != nil {
				return nil, fmt.Errorf("compose %s: step path %q does not reach a declared API", c.Path, prefix)
			}
		}
	}

	if cfg.OIDC != nil {
		h.auth = auth.New(auth.Options{
			OIDC:       *cfg.OIDC,
			Session:    cfg.Session,
			PublicURL:  cfg.Server.PublicURL,
			BasePath:   cfg.Server.BasePath,
			CSRFHeader: cfg.Server.CSRFHeader,
			Store:      deps.Store,
			Sealer:     deps.Sealer,
			Log:        deps.Log,
			HTTP:       deps.HTTP,
		})
	}
	switch {
	case cfg.Frontend.URL != "":
		u, err := url.Parse(cfg.Frontend.URL)
		if err != nil {
			return nil, err
		}
		h.frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deps.Forward.ServeHTTP(w, proxy.With(r, proxy.Target{URL: u, Rest: r.URL.Path}))
		})
	case cfg.Frontend.Dir != "":
		h.frontend = spa(cfg.Frontend.Dir)
	}
	return h, nil
}

// spa serves files, and index.html for client-side routes. A missing path with
// an extension is a real 404, not a route.
func spa(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		name := filepath.Join(dir, filepath.FromSlash(path.Clean("/"+r.URL.Path)))
		if _, err := os.Stat(name); err != nil && path.Ext(r.URL.Path) == "" {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusOK)
		return
	case "/readyz":
		h.ready(w, r)
		return
	}
	if !match.SafePath(r.URL.EscapedPath()) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.Server.MaxBodyBytes)

	base := h.cfg.Server.BasePath
	if r.URL.Path == base || strings.HasPrefix(r.URL.Path, base+"/") {
		if h.auth == nil || !h.auth.Handler(w, r) {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	res := h.table.Lookup(r.URL.Path)
	switch {
	case res.Found:
		h.serveRoute(w, r, res)
	case res.Blocked:
		w.WriteHeader(http.StatusNotFound)
	case h.frontend != nil:
		h.frontend.ServeHTTP(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if h.auth != nil {
		if err := h.auth.Ready(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	if p, ok := h.deps.Store.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// csrfOK is the anti-forgery check on every API call. Browsers can't set
// headers on a WebSocket, so an upgrade proves its origin instead.
func (h *Handler) csrfOK(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		origin, err := url.Parse(r.Header.Get("Origin"))
		if err != nil || origin.Host == "" {
			return false
		}
		if h.cfg.Server.PublicURL != "" {
			public, err := url.Parse(h.cfg.Server.PublicURL)
			return err == nil && origin.Host == public.Host
		}
		return origin.Host == r.Host
	}
	return r.Header.Get(h.cfg.Server.CSRFHeader) != ""
}

func needsUser(token string) bool { return token == config.TokenUser }

func (h *Handler) serveRoute(w http.ResponseWriter, r *http.Request, res match.Result[*route]) {
	rt := res.Value
	policy, scope := rt.policyFor(r.Method, res.Rest)

	if !h.csrfOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var sess *session.Session
	if h.auth != nil {
		var err error
		if sess, err = h.auth.Session(r); err != nil {
			h.deps.Log.Error("session lookup failed", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	if needsUser(policy.Token) && sess == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if rl := policy.RateLimit; rl.Rate > 0 {
		if !h.deps.Limiter.Allow(scope+"|"+rateKey(rl, sess, r), rl.Rate, rl.Burst) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
	}

	var produce func(http.ResponseWriter, *http.Request)
	if rt.plan != nil {
		produce = func(w http.ResponseWriter, r *http.Request) { h.runPlan(w, r, rt.plan) }
	} else {
		var token string
		if h.auth != nil {
			var err error
			if token, err = h.auth.Token(r.Context(), sess, policy.Token); err != nil {
				if errors.Is(err, auth.ErrSessionEnded) {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				h.deps.Log.Error("token unavailable", "err", err)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		target := proxy.Target{
			URL:     rt.targets[res.Service],
			Rest:    res.Rest,
			Token:   token,
			Timeout: policy.Timeout,
			Retries: policy.Retries,
		}
		produce = func(w http.ResponseWriter, r *http.Request) {
			h.deps.Forward.ServeHTTP(w, proxy.With(r, target))
		}
	}
	if policy.Cache > 0 && r.Method == http.MethodGet && r.Header.Get("Upgrade") == "" {
		h.cached(w, r, policy, sess, produce)
		return
	}
	produce(w, r)
}

func rateKey(rl config.RateLimit, sess *session.Session, r *http.Request) string {
	if rl.Per == config.PerSession && sess != nil {
		return "s:" + sess.ID
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}

// cached serves from the cache, filling it once for concurrent callers. The key
// always carries the user unless the route is public, so one user's response
// can never reach another.
func (h *Handler) cached(w http.ResponseWriter, r *http.Request, p config.Effective, sess *session.Session, produce func(http.ResponseWriter, *http.Request)) {
	key := cacheKey(r, p, sess)
	if e, ok := h.deps.Cache.Get(key); ok {
		writeEntry(w, e, "hit")
		return
	}
	filled := false
	e, err := h.deps.Cache.Do(key, func() (*cache.Entry, error) {
		filled = true
		// The fill outlives the first caller, because others may be waiting on it.
		fill := r.Clone(context.WithoutCancel(r.Context()))
		rec, err := capture(0, func(w http.ResponseWriter) { produce(w, fill) })
		if err != nil {
			return nil, err
		}
		e := &cache.Entry{Status: rec.status, Header: rec.header, Body: rec.body.Bytes()}
		if cache.Storable(rec.status, rec.header) && len(e.Body) <= cache.MaxBody {
			e.Stored = true
			h.deps.Cache.Put(key, e, p.Cache)
		}
		return e, nil
	})
	switch {
	case err != nil:
		w.WriteHeader(http.StatusBadGateway)
	case !filled && !e.Stored:
		// It wasn't cacheable, so it was meant for the caller that fetched it.
		produce(w, r)
	default:
		writeEntry(w, e, "miss")
	}
}

func cacheKey(r *http.Request, p config.Effective, sess *session.Session) string {
	owner := "public"
	if p.Token != config.TokenNone {
		owner = "anon"
		if sess != nil {
			owner = "user:" + sess.Sub
		}
	}
	return strings.Join([]string{
		owner, r.URL.RequestURI(),
		r.Header.Get("Accept"), r.Header.Get("Accept-Encoding"), r.Header.Get("Accept-Language"),
	}, "\x00")
}

func writeEntry(w http.ResponseWriter, e *cache.Entry, state string) {
	maps.Copy(w.Header(), e.Header)
	w.Header().Set("X-BFFlash-Cache", state)
	w.WriteHeader(e.Status)
	w.Write(e.Body)
}

func (h *Handler) runPlan(w http.ResponseWriter, r *http.Request, plan *compose.Plan) {
	body, err := plan.Run(r.Context(), func(ctx context.Context, target string) (int, []byte, error) {
		return h.callStep(ctx, r, target)
	})
	if err != nil {
		h.deps.Log.Warn("compose failed", "path", r.URL.Path, "err", err)
		var se *compose.StepError
		if errors.As(err, &se) && (se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden) {
			w.WriteHeader(se.Status) // the frontend can act on these
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// callStep runs a step through the normal route path, so it inherits that API's
// token, timeout and rate rules. The caller's session comes along in its cookie.
func (h *Handler) callStep(ctx context.Context, orig *http.Request, target string) (int, []byte, error) {
	sub, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	if !match.SafePath(sub.URL.EscapedPath()) {
		return 0, nil, fmt.Errorf("unsafe step path")
	}
	res := h.table.Lookup(sub.URL.Path)
	if !res.Found || res.Value.plan != nil {
		return 0, nil, fmt.Errorf("step path %s reaches no API", sub.URL.Path)
	}
	sub.Host = orig.Host
	sub.RemoteAddr = orig.RemoteAddr
	sub.Header.Set("Accept", "application/json")
	sub.Header.Set(h.cfg.Server.CSRFHeader, "1")
	if c := orig.Header.Get("Cookie"); c != "" {
		sub.Header.Set("Cookie", c)
	}
	if id := orig.Header.Get("X-Request-ID"); id != "" {
		sub.Header.Set("X-Request-ID", id)
	}
	rec, err := capture(h.cfg.Server.MaxBodyBytes, func(w http.ResponseWriter) { h.serveRoute(w, sub, res) })
	if err != nil {
		return 0, nil, err
	}
	return rec.status, rec.body.Bytes(), nil
}

// recorder buffers a response. A max of 0 means unbounded.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	max    int64
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if r.max > 0 && int64(r.body.Len()+len(b)) > r.max {
		return 0, errTooLarge
	}
	return r.body.Write(b)
}

var errTooLarge = errors.New("response too large")

// capture runs fn against a recorder. ReverseProxy signals a broken upstream
// body by panicking with ErrAbortHandler, which net/http expects to catch. Here
// that would kill the process from a compose goroutine, or cache half a
// response, so it becomes an ordinary error.
func capture(max int64, fn func(http.ResponseWriter)) (rec *recorder, err error) {
	rec = &recorder{header: http.Header{}, max: max}
	defer func() {
		if p := recover(); p != nil {
			if p != http.ErrAbortHandler {
				panic(p)
			}
			err = errors.New("upstream response was cut off")
		}
	}()
	fn(rec)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return rec, nil
}

// Server is the long-running handle. Reload swaps the compiled handler without
// dropping a request.
type Server struct {
	current atomic.Pointer[Handler]
	deps    *Deps
	http.Handler
}

// New compiles cfg into a Server.
func New(cfg *config.Config, deps *Deps) (*Server, error) {
	h, err := Compile(cfg, deps)
	if err != nil {
		return nil, err
	}
	s := &Server{deps: deps}
	s.current.Store(h)
	s.Handler = observe.Middleware(deps.Log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.current.Load().ServeHTTP(w, r)
	}))
	return s, nil
}

// Reload applies a new config. On any error the running one stays.
func (s *Server) Reload(cfg *config.Config) error {
	h, err := Compile(cfg, s.deps)
	if err != nil {
		return err
	}
	s.current.Store(h)
	return nil
}
