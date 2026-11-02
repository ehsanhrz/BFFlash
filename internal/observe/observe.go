// Package observe is structured request logging and request IDs.
package observe

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"time"
)

const requestIDHeader = "X-Request-ID"

var safeID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap keeps flushing and WebSocket hijacking working through the wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Middleware logs each request. Only the path is logged: query strings carry
// authorization codes, state and logout tokens.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get(requestIDHeader)
		if !safeID.MatchString(id) {
			b := make([]byte, 8)
			rand.Read(b)
			id = hex.EncodeToString(b)
			r.Header.Set(requestIDHeader, id)
		}
		w.Header().Set(requestIDHeader, id)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK // net/http's implicit status
		}
		log.Info("request",
			"id", id,
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"ms", time.Since(start).Milliseconds(),
		)
	})
}
