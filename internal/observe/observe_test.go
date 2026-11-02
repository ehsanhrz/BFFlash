package observe

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func run(t *testing.T, target, id string, h http.HandlerFunc) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var logs bytes.Buffer
	req := httptest.NewRequest("GET", target, nil)
	if id != "" {
		req.Header.Set(requestIDHeader, id)
	}
	rec := httptest.NewRecorder()
	Middleware(slog.New(slog.NewTextHandler(&logs, nil)), h).ServeHTTP(rec, req)
	return rec, logs.String()
}

func TestImplicitStatusIsLoggedAs200(t *testing.T) {
	_, logs := run(t, "/x", "", func(http.ResponseWriter, *http.Request) {})
	if !strings.Contains(logs, "status=200") {
		t.Errorf("logs = %s", logs)
	}
}

func TestQueryStringIsNeverLogged(t *testing.T) {
	_, logs := run(t, "/bff/callback?code=secret-code", "", func(http.ResponseWriter, *http.Request) {})
	if strings.Contains(logs, "secret-code") {
		t.Errorf("logs = %s", logs)
	}
}

func TestRequestID(t *testing.T) {
	var seen string
	h := func(_ http.ResponseWriter, r *http.Request) { seen = r.Header.Get(requestIDHeader) }

	rec, _ := run(t, "/x", "abc-123", h)
	if rec.Header().Get(requestIDHeader) != "abc-123" || seen != "abc-123" {
		t.Errorf("safe id not kept: %q, %q", rec.Header().Get(requestIDHeader), seen)
	}
	rec, _ = run(t, "/x", "bad id\twith junk", h)
	if got := rec.Header().Get(requestIDHeader); got == "" || strings.Contains(got, "junk") || seen != got {
		t.Errorf("unsafe id not replaced: %q, %q", got, seen)
	}
}
