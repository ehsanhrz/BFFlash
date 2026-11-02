package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfflash/internal/config"
	"bfflash/internal/testidp"
)

// echo is an upstream that reports what it received.
func echo(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"path":   r.URL.RequestURI(),
			"auth":   r.Header.Get("Authorization"),
			"cookie": r.Header.Get("Cookie"),
			"xfh":    r.Header.Get("X-Forwarded-Host"),
		})
	}))
	t.Cleanup(s.Close)
	return s
}

type env struct {
	t    *testing.T
	idp  *testidp.IDP
	srv  *Server
	bff  *httptest.Server
	deps *Deps
}

// start boots a server from YAML. {idp} and {self} expand to the provider and
// BFF URLs. The BFF URL has to exist first, because it's in the config.
func start(t *testing.T, yaml string) *env {
	t.Helper()
	idp := testidp.New(t)
	e := &env{t: t, idp: idp}
	var srv atomic.Pointer[Server]
	e.bff = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.Load().ServeHTTP(w, r)
	}))
	t.Cleanup(e.bff.Close)

	cfg, err := config.Parse([]byte(e.expand(yaml)))
	if err != nil {
		t.Fatal(err)
	}
	var logs io.Writer = io.Discard
	if os.Getenv("BFFLASH_TEST_LOG") != "" {
		logs = os.Stderr
	}
	e.deps, err = NewDeps(cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.srv, err = New(cfg, e.deps)
	if err != nil {
		t.Fatal(err)
	}
	srv.Store(e.srv)
	return e
}

func (e *env) expand(s string) string {
	return strings.NewReplacer("{idp}", e.idp.Issuer(), "{self}", e.bff.URL).Replace(s)
}

const oidcBlock = `
server: { public_url: "{self}" }
oidc: { issuer: "{idp}", client_id: bfflash, client_secret: secret }
`

// browser keeps cookies by hand, because Go's jar won't send Secure cookies over
// the plain HTTP that httptest uses.
type browser struct {
	e       *env
	cookies map[string]string
}

func (e *env) browser() *browser { return &browser{e: e, cookies: map[string]string{}} }

func (b *browser) do(method, target string, hdr map[string]string, body io.Reader) *http.Response {
	b.e.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = b.e.bff.URL + target
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		b.e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	var parts []string
	for k, v := range b.cookies {
		parts = append(parts, k+"="+v)
	}
	if len(parts) > 0 {
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	c := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	b.e.t.Cleanup(func() { resp.Body.Close() })
	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			delete(b.cookies, ck.Name)
		} else {
			b.cookies[ck.Name] = ck.Value
		}
	}
	return resp
}

// api is a same-origin fetch: it carries the CSRF header.
func (b *browser) api(method, target string) *http.Response {
	b.e.t.Helper()
	return b.do(method, target, map[string]string{"X-CSRF": "1"}, nil)
}

func (b *browser) follow(target string) *http.Response {
	b.e.t.Helper()
	resp := b.do("GET", target, nil, nil)
	for i := 0; i < 10 && resp.StatusCode/100 == 3; i++ {
		next, _ := resp.Location()
		resp = b.do("GET", next.String(), nil, nil)
	}
	return resp
}

func (b *browser) login() {
	b.e.t.Helper()
	b.follow("/bff/login")
	if b.cookies["__Host-bfflash"] == "" {
		b.e.t.Fatal("login left no session cookie")
	}
}

func text(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func decode(t *testing.T, r *http.Response) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func wantStatus(t *testing.T, r *http.Response, want int) {
	t.Helper()
	if r.StatusCode != want {
		t.Fatalf("%s %s = %d, want %d", r.Request.Method, r.Request.URL.Path, r.StatusCode, want)
	}
}

func TestMinimalConfigWorksUnchanged(t *testing.T) {
	api, web := echo(t), echo(t)
	e := start(t, fmt.Sprintf(`
oidc:
  issuer: "{idp}"
  client_id: bfflash
  client_secret: secret

frontend:
  url: %s

apis:
  - path: /api
    to: %s
`, web.URL, api.URL))
	b := e.browser()
	b.login()
	resp := b.api("GET", "/api/orders/7?x=1")
	wantStatus(t, resp, 200)
	got := decode(t, resp)
	if got["path"] != "/orders/7?x=1" {
		t.Errorf("path = %v", got["path"])
	}
	if !strings.HasPrefix(got["auth"].(string), "Bearer access-") {
		t.Errorf("auth = %v", got["auth"])
	}
	wantStatus(t, b.do("GET", "/some/page", nil, nil), 200)
}

func TestNewBackendEndpointNeedsNoConfigChange(t *testing.T) {
	mux := http.NewServeMux()
	up := httptest.NewServer(mux)
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	wantStatus(t, b.api("GET", "/api/brand-new"), 404)
	mux.HandleFunc("/brand-new", func(http.ResponseWriter, *http.Request) {})
	wantStatus(t, b.api("GET", "/api/brand-new"), 200)
}

func TestLoginKeepsTokensOutOfTheBrowser(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()

	first := b.do("GET", "/bff/login?returnUrl=/dashboard", nil, nil)
	wantStatus(t, first, 302)
	next, _ := first.Location()
	q := next.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Errorf("authorize query = %v", q)
	}
	resp := b.do("GET", next.String(), nil, nil)
	next, _ = resp.Location()
	resp = b.do("GET", next.String(), nil, nil)
	wantStatus(t, resp, 302)
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Errorf("return location = %q", loc)
	}
	if len(b.cookies) != 1 || b.cookies["__Host-bfflash"] == "" {
		t.Fatalf("cookies = %v", b.cookies)
	}
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-bfflash" {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		t.Errorf("cookie = %+v", ck)
	}

	resp = b.api("GET", "/bff/user")
	wantStatus(t, resp, 200)
	raw := text(t, resp)
	for _, leak := range []string{"access-", "refresh-", "id_token", "nonce"} {
		if strings.Contains(raw, leak) {
			t.Errorf("/bff/user leaked %q: %s", leak, raw)
		}
	}
	if !strings.Contains(raw, `"sub":"alice"`) || !strings.Contains(raw, `"name":"Alice"`) {
		t.Errorf("/bff/user = %s", raw)
	}
}

func TestLoginRejectsForgedState(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	b := e.browser()
	wantStatus(t, b.do("GET", "/bff/callback?code=x&state=y", nil, nil), 400) // no login cookie
	b.do("GET", "/bff/login", nil, nil)
	wantStatus(t, b.do("GET", "/bff/callback?code=x&state=forged", nil, nil), 400)
	if b.cookies["__Host-bfflash"] != "" {
		t.Error("session created from a forged callback")
	}
}

func TestSessionIDRotatesOnLogin(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	b := e.browser()
	b.login()
	old := b.cookies["__Host-bfflash"]
	b.login()
	if b.cookies["__Host-bfflash"] == old {
		t.Fatal("session ID did not rotate")
	}
	stale := e.browser()
	stale.cookies["__Host-bfflash"] = old
	wantStatus(t, stale.api("GET", "/bff/user"), 401)
}

func TestReturnURLCannotLeaveTheSite(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	for _, evil := range []string{"https://evil.test/", "//evil.test", "/\\evil.test", "evil.test", "javascript:alert(1)"} {
		b := e.browser()
		first := b.do("GET", "/bff/login?returnUrl="+url.QueryEscape(evil), nil, nil)
		next, _ := first.Location()
		resp := b.do("GET", next.String(), nil, nil)
		next, _ = resp.Location()
		resp = b.do("GET", next.String(), nil, nil)
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Errorf("returnUrl %q redirected to %q", evil, loc)
		}
	}
}

func TestAPIWithoutSessionIs401NotRedirect(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	resp := e.browser().api("GET", "/api/x")
	wantStatus(t, resp, 401)
	if resp.Header.Get("Location") != "" {
		t.Error("API redirected")
	}
}

func TestCSRFHeaderRequiredOnEveryMethod(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	b.login()
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		wantStatus(t, b.do(m, "/api/x", nil, nil), 401)
		wantStatus(t, b.api(m, "/api/x"), 200)
	}
}

func TestCSRFHeaderNameIsConfigurable(t *testing.T) {
	up := echo(t)
	e := start(t, `server: { csrf_header: X-Mine }
defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	wantStatus(t, b.api("GET", "/api/x"), 401)
	wantStatus(t, b.do("GET", "/api/x", map[string]string{"X-Mine": "1"}, nil), 200)
}

func TestWebSocketUpgradeProvesOriginInstead(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	b.login()
	wsHdr := func(origin string) map[string]string {
		return map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Origin": origin}
	}
	wantStatus(t, b.do("GET", "/api/ws", wsHdr("https://evil.test"), nil), 401)
	wantStatus(t, b.do("GET", "/api/ws", wsHdr(""), nil), 401)
	wantStatus(t, b.do("GET", "/api/ws", wsHdr(e.bff.URL), nil), 200)
}

func TestBrowserCredentialsNeverReachUpstream(t *testing.T) {
	api, web := echo(t), echo(t)
	e := start(t, oidcBlock+`frontend: { url: "`+web.URL+`" }
apis: [{ path: /api, to: "`+api.URL+`" }, { path: /pub, to: "`+api.URL+`", token: none }]`)
	b := e.browser()
	b.login()
	hdr := map[string]string{"X-CSRF": "1", "Authorization": "Bearer forged"}

	got := decode(t, b.do("GET", "/api/x", hdr, nil))
	if got["cookie"] != "" || got["auth"] == "Bearer forged" {
		t.Errorf("api saw %v", got)
	}
	got = decode(t, b.do("GET", "/pub/x", hdr, nil))
	if got["cookie"] != "" || got["auth"] != "" {
		t.Errorf("public api saw %v", got)
	}
	got = decode(t, b.do("GET", "/page", hdr, nil))
	if got["cookie"] != "" || got["auth"] != "" {
		t.Errorf("frontend saw %v", got)
	}
}

func TestPrefixRouting(t *testing.T) {
	orders, web := echo(t), echo(t)
	e := start(t, `defaults: { token: none }
frontend: { url: "`+web.URL+`" }
apis: [{ path: /api/orders, to: "`+orders.URL+`/v1" }]`)
	b := e.browser()
	if got := decode(t, b.api("GET", "/api/orders/x")); got["path"] != "/v1/x" {
		t.Errorf("path = %v", got["path"])
	}
	if got := decode(t, b.api("GET", "/api/orders")); got["path"] != "/v1" {
		t.Errorf("bare prefix path = %v", got["path"])
	}
	// Past the segment boundary this is the frontend's, with its path intact.
	if got := decode(t, b.api("GET", "/api/ordersfoo")); got["path"] != "/api/ordersfoo" {
		t.Errorf("ordersfoo = %v", got["path"])
	}
}

func TestTraversalIsRejected(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api/orders, to: "`+up.URL+`/v1" }]`)

	u, _ := url.Parse(e.bff.URL)
	for _, p := range []string{
		"/api/orders/../admin", "/api/orders/%2e%2e/admin", "/api/orders/..%2fadmin",
		"/api/orders/%252e%252e/admin", "/api/orders//admin", "/api/orders/a%5cb",
	} {
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nX-CSRF: 1\r\nConnection: close\r\n\r\n", p)
		raw, _ := io.ReadAll(conn)
		conn.Close()
		if !strings.HasPrefix(string(raw), "HTTP/1.1 400") {
			t.Errorf("%s: %.40s", p, raw)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("upstream saw %d requests", hits.Load())
	}
}

func TestServiceTemplate(t *testing.T) {
	var host atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		host.Store(r.Host + " " + r.URL.Path)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	port := u.Port()

	// *.localhost isn't guaranteed to resolve, so route every name to the upstream.
	e := start(t, `defaults: { token: none }
apis: [{ path: "/svc/{service}", to: "http://{service}.internal:`+port+`/base", allow: [billing] }]`)
	dial := &net.Dialer{}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context_, network, _ string) (net.Conn, error) {
		return dial.DialContext(ctx, network, u.Host)
	}
	useTransport(e, tr)

	b := e.browser()
	wantStatus(t, b.api("GET", "/svc/billing/invoices"), 200)
	if got := host.Load(); got != "billing.internal:"+port+" /base/invoices" {
		t.Errorf("upstream saw %v", got)
	}
	host.Store("")
	wantStatus(t, b.api("GET", "/svc/vault/secrets"), 404)
	if host.Load() != "" {
		t.Error("request reached a service outside allow")
	}
}

func TestRefreshOnExpiry(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	e.idp.TokenTTL = 10 * time.Second // inside the refresh margin, so it's already stale
	b := e.browser()
	b.login()
	e.idp.TokenTTL = time.Hour

	first := decode(t, b.api("GET", "/api/x"))
	second := decode(t, b.api("GET", "/api/x"))
	if e.idp.RefreshCalls.Load() != 1 {
		t.Errorf("refresh calls = %d", e.idp.RefreshCalls.Load())
	}
	if first["auth"] != second["auth"] {
		t.Error("refreshed token was not stored")
	}
}

func TestConcurrentRefreshHitsProviderOnce(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	e.idp.TokenTTL = 10 * time.Second
	b := e.browser()
	b.login()
	e.idp.TokenTTL = time.Hour

	// The provider rotates refresh tokens, so a duplicate refresh fails outright.
	var wg sync.WaitGroup
	statuses := make([]int, 20)
	cookie := "__Host-bfflash=" + b.cookies["__Host-bfflash"]
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", e.bff.URL+"/api/x", nil)
			req.Header.Set("Cookie", cookie)
			req.Header.Set("X-CSRF", "1")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for _, s := range statuses {
		if s != 200 {
			t.Errorf("statuses = %v", statuses)
			break
		}
	}
	if n := e.idp.RefreshCalls.Load(); n != 1 {
		t.Errorf("refresh calls = %d", n)
	}
}

func TestRefusedRefreshEndsTheSession(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	e.idp.TokenTTL = 10 * time.Second
	b := e.browser()
	b.login()
	e.idp.RefuseRefresh.Store(true)
	wantStatus(t, b.api("GET", "/api/x"), 401)
	wantStatus(t, b.api("GET", "/bff/user"), 401)
}

func TestTokenModes(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis:
  - { path: /user, to: "`+up.URL+`" }
  - { path: /client, to: "`+up.URL+`", token: client }
  - { path: /both, to: "`+up.URL+`", token: user_or_client }
  - { path: /opt, to: "`+up.URL+`", token: user_or_none }
  - { path: /none, to: "`+up.URL+`", token: none }
`)
	anon, in := e.browser(), e.browser()
	in.login()
	const user, client = "Bearer access-", "Bearer client-token"
	cases := []struct {
		path     string
		anon, in string // expected auth prefix, "x" for a 401
	}{
		{"/user", "x", user},
		{"/client", client, client},
		{"/both", client, user},
		{"/opt", "", user},
		{"/none", "", ""},
	}
	check := func(b *browser, path, want string) {
		t.Helper()
		resp := b.api("GET", path+"/z")
		if want == "x" {
			wantStatus(t, resp, 401)
			return
		}
		wantStatus(t, resp, 200)
		got := decode(t, resp)["auth"].(string)
		if (want == "" && got != "") || !strings.HasPrefix(got, want) {
			t.Errorf("%s auth = %q, want %q", path, got, want)
		}
	}
	for _, c := range cases {
		check(anon, c.path, c.anon)
		check(in, c.path, c.in)
	}
	if n := e.idp.ClientCalls.Load(); n != 1 {
		t.Errorf("client token fetched %d times, want it cached", n)
	}
}

func TestRuleOverridesTheAPI(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis:
  - path: /api
    to: "`+up.URL+`"
    rules:
      - { match: GET /public/**, token: none }
`)
	b := e.browser()
	wantStatus(t, b.api("GET", "/api/public/a/b"), 200)
	wantStatus(t, b.api("POST", "/api/public/a/b"), 401)
	wantStatus(t, b.api("GET", "/api/private"), 401)
}

func TestCacheNeverCrossesUsers(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`", cache: 1m }]`)
	alice := e.browser()
	alice.login()
	e.idp.Sub = "bob"
	bob := e.browser()
	bob.login()

	r1 := alice.api("GET", "/api/me")
	a := decode(t, r1)
	r2 := alice.api("GET", "/api/me")
	if r2.Header.Get("X-BFFlash-Cache") != "hit" {
		t.Errorf("second call = %q", r2.Header.Get("X-BFFlash-Cache"))
	}
	r3 := bob.api("GET", "/api/me")
	if r3.Header.Get("X-BFFlash-Cache") != "miss" {
		t.Errorf("bob = %q", r3.Header.Get("X-BFFlash-Cache"))
	}
	if b := decode(t, r3); a["auth"] == b["auth"] {
		t.Error("bob received alice's response")
	}
}

func TestPublicCacheIsSharedAndCoalesced(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`", cache: 1m }]`)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", e.bff.URL+"/api/x", nil)
			req.Header.Set("X-CSRF", "1")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
				t.Errorf("body = %q", b)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("upstream calls = %d", calls.Load())
	}
}

func TestUnstorableResponsesAreNotCached(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/cookie":
			w.Header().Set("Set-Cookie", "a=b")
		case "/private":
			w.Header().Set("Cache-Control", "private")
		case "/nostore":
			w.Header().Set("Cache-Control", "no-store")
		case "/fail":
			w.WriteHeader(500)
		}
	}))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`", cache: 1m }]`)
	b := e.browser()
	for _, p := range []string{"/cookie", "/private", "/nostore", "/fail"} {
		calls.Store(0)
		b.api("GET", "/api"+p)
		b.api("GET", "/api"+p)
		if calls.Load() != 2 {
			t.Errorf("%s: upstream calls = %d", p, calls.Load())
		}
	}
}

func TestOnlyGETIsCached(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`", cache: 1m }]`)
	b := e.browser()
	b.api("POST", "/api/x")
	b.api("POST", "/api/x")
	if calls.Load() != 2 {
		t.Errorf("upstream calls = %d", calls.Load())
	}
}

func TestCutOffResponseIsNotCached(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// Flush first: the break has to land mid-body, after the headers.
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		io.WriteString(w, "whole")
	}))
	up.Config.ErrorLog = nil
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`", cache: 1m }]`)
	b := e.browser()
	wantStatus(t, b.api("GET", "/api/x"), 502)
	resp := b.api("GET", "/api/x")
	if got := text(t, resp); got != "whole" {
		t.Errorf("body = %q", got)
	}
}

func TestRateLimit(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`", rate_limit: 1/h per session }]`)
	a, b := e.browser(), e.browser()
	a.login()
	b.login()
	wantStatus(t, a.api("GET", "/api/x"), 200)
	resp := a.api("GET", "/api/x")
	wantStatus(t, resp, 429)
	if resp.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	wantStatus(t, b.api("GET", "/api/x"), 200)
}

func TestBackchannelLogout(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	post := func(token string) *http.Response {
		form := url.Values{"logout_token": {token}}
		resp, err := http.PostForm(e.bff.URL+"/bff/backchannel-logout", form)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	e.idp.SID = "sid-target"
	target := e.browser()
	target.login()
	e.idp.SID = "sid-other"
	other := e.browser()
	other.login()

	const event = "http://schemas.openid.net/event/backchannel-logout"
	bad := map[string]string{
		"garbage":     "not-a-jwt",
		"wrong aud":   e.idp.LogoutToken(map[string]any{"aud": "someone-else"}),
		"wrong iss":   e.idp.LogoutToken(map[string]any{"iss": "https://evil.test"}),
		"expired":     e.idp.LogoutToken(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}),
		"no event":    e.idp.LogoutToken(map[string]any{"events": nil}),
		"other event": e.idp.LogoutToken(map[string]any{"events": map[string]any{"x": map[string]any{}}}),
		"has nonce":   e.idp.LogoutToken(map[string]any{"nonce": "n"}),
		"id token":    e.idp.IDToken("n"),
		"stale iat":   e.idp.LogoutToken(map[string]any{"iat": time.Now().Add(-time.Hour).Unix()}),
		"no subject":  e.idp.LogoutToken(map[string]any{"sub": nil, "sid": nil}),
		"unsigned":    unsigned(e.idp, event),
	}
	for name, tok := range bad {
		if r := post(tok); r.StatusCode != 400 {
			t.Errorf("%s: status = %d", name, r.StatusCode)
		}
	}
	wantStatus(t, target.api("GET", "/api/x"), 200)

	wantStatus(t, post(e.idp.LogoutToken(map[string]any{"sid": "sid-target"})), 200)
	wantStatus(t, target.api("GET", "/api/x"), 401)
	wantStatus(t, other.api("GET", "/api/x"), 200)
}

func unsigned(idp *testidp.IDP, event string) string {
	enc := func(s string) string {
		return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64Std(s)), "=")
	}
	body := fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":"alice","iat":%d,"exp":%d,"events":{%q:{}}}`,
		idp.Issuer(), idp.ClientID, time.Now().Unix(), time.Now().Add(time.Minute).Unix(), event)
	return enc(`{"alg":"none"}`) + "." + enc(body) + "."
}

func TestLogout(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	b.login()

	// Neither a cross-site link nor a form post can sign the user out.
	wantStatus(t, b.do("GET", "/bff/logout", nil, nil), 400)
	wantStatus(t, b.do("GET", "/bff/logout?token=guess", nil, nil), 400)
	wantStatus(t, b.do("POST", "/bff/logout", nil, nil), 401)
	wantStatus(t, b.api("GET", "/api/x"), 200)

	resp := b.api("POST", "/bff/logout")
	wantStatus(t, resp, 200)
	redirect := decode(t, resp)["redirect"].(string)
	if !strings.HasPrefix(redirect, e.idp.Issuer()+"/end-session?") || !strings.Contains(redirect, "id_token_hint=") {
		t.Errorf("redirect = %s", redirect)
	}
	if b.cookies["__Host-bfflash"] != "" {
		t.Error("cookie not cleared")
	}
}

func TestLogoutLinkFromUserEndpoint(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	b.login()
	cookie := b.cookies["__Host-bfflash"]
	link := decode(t, b.api("GET", "/bff/user"))["logout_url"].(string)
	wantStatus(t, b.do("GET", link, nil, nil), 302)
	replay := e.browser()
	replay.cookies["__Host-bfflash"] = cookie
	wantStatus(t, replay.api("GET", "/api/x"), 401)
}

func TestUserEndpointNeedsCSRFHeader(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	b := e.browser()
	b.login()
	wantStatus(t, b.do("GET", "/bff/user", nil, nil), 401)
}

func TestExpiredAbsoluteLifetime(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`session: { idle_ttl: 1h, absolute_ttl: 1h }
apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	b.login()
	wantStatus(t, b.api("GET", "/api/x"), 200)

	// Age the session past its limit while the store still holds it.
	ctx := context.Background()
	sess, err := e.deps.Store.Get(ctx, b.cookies["__Host-bfflash"])
	if err != nil || sess == nil {
		t.Fatalf("get = %v, %v", sess, err)
	}
	sess.CreatedAt = time.Now().Add(-2 * time.Hour)
	if err := e.deps.Store.Put(ctx, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, b.api("GET", "/api/x"), 401)
}

func TestLoginRejectsReplayedNonce(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	e.idp.ForceNonce = "from-another-login"
	b := e.browser()
	resp := b.follow("/bff/login")
	wantStatus(t, resp, 502)
	if b.cookies["__Host-bfflash"] != "" {
		t.Error("session created from a replayed ID token")
	}
}

func TestWebSocketOriginWithoutPublicURL(t *testing.T) {
	up := echo(t)
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	hdr := func(origin string) map[string]string {
		return map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Origin": origin}
	}
	wantStatus(t, b.do("GET", "/api/ws", hdr("https://evil.test"), nil), 401)
	wantStatus(t, b.do("GET", "/api/ws", hdr(e.bff.URL), nil), 200)
}

func TestSharedFillNeverLeaksAnUnstorableResponse(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Only the first caller gets the cookie, so a leak shows up as a waiter
		// receiving it. The delay holds the others inside the same fill.
		if calls.Add(1) == 1 {
			w.Header().Set("Set-Cookie", "owner=first")
		}
		time.Sleep(100 * time.Millisecond)
	}))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`", cache: 1m }]`)

	var leaked atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", e.bff.URL+"/api/x", nil)
			req.Header.Set("X-CSRF", "1")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			if resp.Header.Get("Set-Cookie") != "" {
				leaked.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := leaked.Load(); n != 1 {
		t.Errorf("%d callers received the cookie, want only the one it was set for", n)
	}
}

func composeUp(t *testing.T) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/me":
			fmt.Fprintf(w, `{"id":42,"name":"Alice","auth":%q}`, r.Header.Get("Authorization"))
		case "/orders":
			fmt.Fprintf(w, `[{"user":%q}]`, r.URL.Query().Get("user"))
		case "/down":
			w.WriteHeader(503)
		case "/denied":
			w.WriteHeader(403)
		case "/cut":
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(up.Close)
	return up
}

func TestCompose(t *testing.T) {
	up := composeUp(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]
compose:
  - path: /api/dashboard
    steps:
      - { id: me, get: "/api/users/me" }
      - { id: orders, get: "/api/orders?user=${steps.me.body.id}" }
      - { id: extra, get: "/api/down", optional: true }
    respond: |
      {"name": steps.me.body.name, "auth": steps.me.body.auth,
       "orders": steps.orders.body, "extra": steps.extra.ok}
  - path: /api/broken
    steps: [{ id: a, get: "/api/down" }]
    respond: "{}"
  - path: /api/denied-view
    steps: [{ id: a, get: "/api/denied" }]
    respond: "{}"
  - path: /api/cut-view
    steps: [{ id: a, get: "/api/cut" }]
    respond: "{}"
`)
	wantStatus(t, e.browser().api("GET", "/api/dashboard"), 401)

	b := e.browser()
	b.login()
	resp := b.api("GET", "/api/dashboard")
	wantStatus(t, resp, 200)
	got := decode(t, resp)
	if got["name"] != "Alice" || got["extra"] != false {
		t.Errorf("got = %v", got)
	}
	if !strings.HasPrefix(got["auth"].(string), "Bearer access-") {
		t.Errorf("step had no user token: %v", got["auth"])
	}
	if o := got["orders"].([]any)[0].(map[string]any); o["user"] != "42" {
		t.Errorf("orders = %v", o)
	}

	wantStatus(t, b.api("GET", "/api/broken"), 502)
	wantStatus(t, b.api("GET", "/api/denied-view"), 403)
	// A broken upstream body must fail one request, not the process.
	wantStatus(t, b.api("GET", "/api/cut-view"), 502)
	wantStatus(t, b.api("GET", "/api/dashboard"), 200)
}

func TestComposeIsCached(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"v":1}`)
	}))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`" }]
compose:
  - { path: /view, cache: 1m, steps: [{ id: a, get: "/api/a" }], respond: "{'v': steps.a.body.v}" }
`)
	b := e.browser()
	wantStatus(t, b.api("GET", "/view"), 200)
	wantStatus(t, b.api("GET", "/view"), 200)
	if calls.Load() != 1 {
		t.Errorf("upstream calls = %d", calls.Load())
	}
}

func TestComposeRoutesBadStepsAtCompileTime(t *testing.T) {
	parse := func(y string) error {
		cfg, err := config.Parse([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		deps, _ := NewDeps(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		_, err = Compile(cfg, deps)
		return err
	}
	if err := parse(`defaults: { token: none }
apis: [{ path: /api, to: "http://x" }]
compose: [{ path: /v, steps: [{ id: a, get: /nowhere }], respond: "{}" }]`); err == nil {
		t.Error("step to an undeclared path compiled")
	}
	if err := parse(`defaults: { token: none }
compose:
  - { path: /a, steps: [{ id: x, get: /b }], respond: "{}" }
  - { path: /b, steps: [{ id: x, get: /a }], respond: "{}" }`); err == nil {
		t.Error("compose calling compose compiled")
	}
}

func TestComposeValueCannotRedirectToAnotherCompose(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"next":"loop"}`)
	}))
	defer up.Close()
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`" }]
compose:
  - path: /api/loop
    steps:
      - { id: a, get: "/api/a" }
      - { id: b, get: "/api/${steps.a.body.next}" }
    respond: "{}"
`)
	wantStatus(t, e.browser().api("GET", "/api/loop"), 502)
}

func TestReload(t *testing.T) {
	first, second := echo(t), echo(t)
	e := start(t, `defaults: { token: none }
apis: [{ path: /api, to: "`+first.URL+`/one" }]`)
	b := e.browser()
	if got := decode(t, b.api("GET", "/api/x")); got["path"] != "/one/x" {
		t.Fatalf("path = %v", got["path"])
	}

	bad, err := config.Parse([]byte(`defaults: { token: none }
apis: [{ path: /api, to: "http://x" }]
compose: [{ path: /v, steps: [{ id: a, get: /nowhere }], respond: "{}" }]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Reload(bad); err == nil {
		t.Fatal("bad reload accepted")
	}
	if got := decode(t, b.api("GET", "/api/x")); got["path"] != "/one/x" {
		t.Errorf("bad reload changed routing: %v", got["path"])
	}

	good, _ := config.Parse([]byte(`defaults: { token: none }
apis: [{ path: /api, to: "` + second.URL + `/two" }]`))
	if err := e.srv.Reload(good); err != nil {
		t.Fatal(err)
	}
	if got := decode(t, b.api("GET", "/api/x")); got["path"] != "/two/x" {
		t.Errorf("path = %v", got["path"])
	}
}

func TestSessionsSurviveReload(t *testing.T) {
	up := echo(t)
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "`+up.URL+`" }]`)
	b := e.browser()
	b.login()
	next, _ := config.Parse([]byte(e.expand(oidcBlock + `apis: [{ path: /api, to: "` + up.URL + `/v2" }]`)))
	if err := e.srv.Reload(next); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, b.api("GET", "/api/x"), 200)
}

func TestFrontendDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<app>"), 0o644)
	os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "a.js"), []byte("js"), 0o644)
	e := start(t, `defaults: { token: none }
frontend: { dir: "`+filepath.ToSlash(dir)+`" }
apis: [{ path: /api, to: "http://x" }]`)
	b := e.browser()
	for path, want := range map[string]string{"/": "<app>", "/orders/7": "<app>", "/assets/a.js": "js"} {
		resp := b.do("GET", path, nil, nil)
		if got := text(t, resp); got != want {
			t.Errorf("%s = %q (%d)", path, got, resp.StatusCode)
		}
	}
	wantStatus(t, b.do("GET", "/missing.js", nil, nil), 404)
	wantStatus(t, b.do("POST", "/", nil, nil), 405)
}

func TestHealthAndUnknownManagementPaths(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	b := e.browser()
	wantStatus(t, b.do("GET", "/healthz", nil, nil), 200)
	wantStatus(t, b.do("GET", "/readyz", nil, nil), 200)
	wantStatus(t, b.do("GET", "/bff/nope", nil, nil), 404)
	wantStatus(t, b.do("GET", "/bff", nil, nil), 404)
}

func TestReadyzFailsWhileProviderIsDown(t *testing.T) {
	e := start(t, oidcBlock+`apis: [{ path: /api, to: "http://x" }]`)
	e.idp.Server.Close()
	wantStatus(t, e.browser().do("GET", "/readyz", nil, nil), 503)
}

func TestRequestBodyLimit(t *testing.T) {
	var size atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		size.Store(n)
	}))
	defer up.Close()
	e := start(t, `server: { max_body_bytes: 10 }
defaults: { token: none }
apis: [{ path: /api, to: "`+up.URL+`" }]`)
	resp := e.browser().do("POST", "/api/x", map[string]string{"X-CSRF": "1"}, strings.NewReader(strings.Repeat("x", 1000)))
	if resp.StatusCode == 200 && size.Load() >= 1000 {
		t.Errorf("status = %d, upstream read %d bytes", resp.StatusCode, size.Load())
	}
}
