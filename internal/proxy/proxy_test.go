package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func forward(t *testing.T, upstream string, tg Target, req *http.Request) *http.Response {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	tg.URL = u
	rec := httptest.NewRecorder()
	New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil).ServeHTTP(rec, With(req, tg))
	return rec.Result()
}

func TestRewriteAndHeaders(t *testing.T) {
	var got *http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r }))
	defer up.Close()

	req := httptest.NewRequest("GET", "/api/orders/a%20b?x=1", nil)
	req.Header.Set("Cookie", "__Host-bfflash=secret")
	req.Header.Set("Authorization", "Bearer forged")
	forward(t, up.URL+"/v1", Target{Rest: "/a b", Token: "real"}, req)

	if got.URL.EscapedPath() != "/v1/a%20b" || got.URL.RawQuery != "x=1" {
		t.Errorf("url = %s", got.URL)
	}
	if got.Header.Get("Cookie") != "" {
		t.Error("cookie reached the upstream")
	}
	if a := got.Header.Get("Authorization"); a != "Bearer real" {
		t.Errorf("authorization = %q", a)
	}
}

func TestBrowserAuthorizationIsStrippedWithoutToken(t *testing.T) {
	var auth atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
	}))
	defer up.Close()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer forged")
	forward(t, up.URL, Target{}, req)
	if a := auth.Load(); a != "" {
		t.Errorf("authorization = %q", a)
	}
}

func TestTimeoutIs504AndCoversHeadersOnly(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(150 * time.Millisecond)
			io.WriteString(w, "done")
			return
		}
		<-release
	}))
	defer up.Close()
	defer close(release)

	resp := forward(t, up.URL, Target{Rest: "/slow", Timeout: 50 * time.Millisecond}, httptest.NewRequest("GET", "/slow", nil))
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("slow status = %d", resp.StatusCode)
	}
	resp = forward(t, up.URL, Target{Rest: "/stream", Timeout: 50 * time.Millisecond}, httptest.NewRequest("GET", "/stream", nil))
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "done" {
		t.Errorf("stream = %d %q", resp.StatusCode, body)
	}
}

func TestRetries(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer up.Close()

	resp := forward(t, up.URL, Target{Retries: 2}, httptest.NewRequest("GET", "/x", nil))
	if resp.StatusCode != 200 || calls.Load() != 3 {
		t.Errorf("GET status = %d, calls = %d", resp.StatusCode, calls.Load())
	}

	calls.Store(0)
	post := httptest.NewRequest("POST", "/x", strings.NewReader("{}"))
	resp = forward(t, up.URL, Target{Retries: 2}, post)
	if resp.StatusCode != http.StatusBadGateway || calls.Load() != 1 {
		t.Errorf("POST status = %d, calls = %d", resp.StatusCode, calls.Load())
	}
}

func TestDeadUpstreamIs502(t *testing.T) {
	resp := forward(t, "http://127.0.0.1:1", Target{}, httptest.NewRequest("GET", "/x", nil))
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
