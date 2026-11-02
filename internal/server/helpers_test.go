package server

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"

	"bfflash/internal/proxy"
)

type context_ = context.Context

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// useTransport points the server's forwarder at a custom transport.
func useTransport(e *env, tr http.RoundTripper) {
	*e.deps.Forward = *proxy.New(slog.New(slog.NewTextHandler(io.Discard, nil)), tr)
}
