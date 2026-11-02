// Package proxy forwards requests to upstreams.
package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Target says where one request goes and how. It travels in the request
// context because a single reverse proxy serves every route.
type Target struct {
	URL     *url.URL
	Rest    string // appended to URL's path
	Token   string // sent as a bearer token when set
	Timeout time.Duration
	Retries int
}

type targetKey struct{}

// With attaches a Target to a request.
func With(r *http.Request, t Target) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), targetKey{}, &t))
}

var errTimeout = errors.New("upstream timeout")

// Forwarder is the shared reverse proxy.
type Forwarder struct {
	rp *httputil.ReverseProxy
}

// New builds a Forwarder. A nil base uses a clone of the default transport.
func New(log *slog.Logger, base http.RoundTripper) *Forwarder {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	return &Forwarder{rp: &httputil.ReverseProxy{
		Rewrite:   rewrite,
		Transport: &transport{base: base},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status := http.StatusBadGateway
			if errors.Is(err, errTimeout) {
				status = http.StatusGatewayTimeout
			}
			if !errors.Is(err, context.Canceled) {
				log.Warn("upstream failed", "path", r.URL.Path, "status", status, "err", err)
			}
			w.WriteHeader(status)
		},
	}}
}

func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.rp.ServeHTTP(w, r)
}

func rewrite(pr *httputil.ProxyRequest) {
	t := pr.In.Context().Value(targetKey{}).(*Target)
	out := pr.Out
	out.URL.Scheme = t.URL.Scheme
	out.URL.Host = t.URL.Host
	out.URL.Path = joinPath(t.URL.Path, t.Rest)
	out.URL.RawPath = ""
	out.Host = t.URL.Host

	// The browser's credentials end here. Only the BFF speaks for the user.
	out.Header.Del("Cookie")
	out.Header.Del("Authorization")
	if t.Token != "" {
		out.Header.Set("Authorization", "Bearer "+t.Token)
	}
	pr.SetXForwarded()
}

func joinPath(base, rest string) string {
	base = strings.TrimRight(base, "/")
	if base == "" && rest == "" {
		return "/"
	}
	return base + rest
}

// transport applies the timeout and retries. The timeout covers the wait for
// response headers, not the body, so streams and WebSockets live on.
type transport struct {
	base http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, _ := req.Context().Value(targetKey{}).(*Target)
	if target == nil {
		target = &Target{}
	}
	retries := 0
	if retryable(req) {
		retries = target.Retries
	}
	for attempt := 0; ; attempt++ {
		resp, err := t.once(req, target.Timeout)
		if attempt == retries || !shouldRetry(resp, err) {
			return resp, err
		}
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
		}
		select {
		case <-time.After(100 * time.Millisecond << attempt):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

func (t *transport) once(req *http.Request, timeout time.Duration) (*http.Response, error) {
	if timeout <= 0 {
		return t.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancelCause(req.Context())
	timer := time.AfterFunc(timeout, func() { cancel(errTimeout) })
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	timer.Stop()
	if err != nil {
		timedOut := errors.Is(context.Cause(ctx), errTimeout)
		cancel(nil)
		if timedOut {
			return nil, errTimeout
		}
		return nil, err
	}
	// A 101 body is the hijacked connection, which must stay a ReadWriteCloser.
	// It ends with the request context, so the cancel is not lost.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel(nil)
	return err
}

// retryable allows idempotent methods only, and never a body that has already
// been consumed by a failed attempt.
func retryable(req *http.Request) bool {
	if req.Header.Get("Upgrade") != "" {
		return false
	}
	if req.Body != nil && req.Body != http.NoBody {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled)
	}
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}
