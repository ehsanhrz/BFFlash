// Command echo is the upstream for the Keycloak smoke test. It reports what
// arrived, with the token reduced to its username and a short hash, so a refresh
// is visible without printing a credential.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	log.Fatal(http.ListenAndServe(":9090", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"path": r.URL.RequestURI(), "cookie_seen": r.Header.Get("Cookie") != ""}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if parts := strings.Split(tok, "."); len(parts) == 3 {
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			json.Unmarshal(raw, &claims)
			out["user"] = claims["preferred_username"]
			out["token_id"] = fmt.Sprintf("%x", sha256.Sum256([]byte(tok)))[:8]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})))
}
