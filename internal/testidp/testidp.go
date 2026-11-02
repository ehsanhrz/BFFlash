// Package testidp is a small in-process OIDC provider for tests. It signs real
// JWTs and enforces PKCE, so a client that skips either step fails.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

type grant struct {
	challenge, nonce string
}

// IDP is a running provider. Fields may be set before the first request.
type IDP struct {
	Server   *httptest.Server
	ClientID string
	Secret   string
	Sub      string
	SID      string
	Name     string
	// TokenTTL is the lifetime of issued access tokens.
	TokenTTL time.Duration

	RefreshCalls atomic.Int32
	ClientCalls  atomic.Int32
	// RefuseRefresh makes refresh grants fail with invalid_grant.
	RefuseRefresh atomic.Bool
	// ForceNonce replaces the nonce in issued ID tokens, as a replay would.
	ForceNonce string

	key    *rsa.PrivateKey
	signer jose.Signer

	mu      sync.Mutex
	grants  map[string]grant
	refresh map[string]bool
}

// New starts a provider and stops it when the test ends.
func New(t *testing.T) *IDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	p := &IDP{
		ClientID: "bfflash", Secret: "secret", Sub: "alice", SID: "sid-1", Name: "Alice",
		TokenTTL: time.Hour,
		key:      key, signer: signer,
		grants: map[string]grant{}, refresh: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

// Issuer is the provider's issuer URL.
func (p *IDP) Issuer() string { return p.Server.URL }

func (p *IDP) discovery(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.Issuer() + "/authorize",
		"token_endpoint":                        p.Issuer() + "/token",
		"jwks_uri":                              p.Issuer() + "/jwks",
		"end_session_endpoint":                  p.Issuer() + "/end-session",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *IDP) jwks(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
}

func (p *IDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "pkce required", http.StatusBadRequest)
		return
	}
	code := base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	p.mu.Lock()
	p.grants[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	p.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *IDP) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.Secret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.exchangeCode(w, r)
	case "refresh_token":
		p.RefreshCalls.Add(1)
		time.Sleep(20 * time.Millisecond) // widen the window for concurrent callers
		old := r.PostForm.Get("refresh_token")
		p.mu.Lock()
		valid := p.refresh[old]
		delete(p.refresh, old) // rotation: a second use of this token fails
		p.mu.Unlock()
		if !valid || p.RefuseRefresh.Load() {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		p.respond(w, "")
	case "client_credentials":
		p.ClientCalls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "client-token", "token_type": "Bearer", "expires_in": 3600})
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (p *IDP) exchangeCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, ok := p.grants[code]
	delete(p.grants, code)
	p.mu.Unlock()
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	p.respond(w, g.nonce)
}

func (p *IDP) respond(w http.ResponseWriter, nonce string) {
	refresh := "refresh-" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	p.mu.Lock()
	p.refresh[refresh] = true
	p.mu.Unlock()
	body := map[string]any{
		"access_token":  "access-" + refresh,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(p.TokenTTL.Seconds()),
	}
	if p.ForceNonce != "" {
		nonce = p.ForceNonce
	}
	if nonce != "" {
		body["id_token"] = p.IDToken(nonce)
	}
	json.NewEncoder(w).Encode(body)
}

// IDToken signs an ID token.
func (p *IDP) IDToken(nonce string) string {
	return p.Sign(map[string]any{
		"iss": p.Issuer(), "aud": p.ClientID, "sub": p.Sub, "sid": p.SID, "name": p.Name,
		"nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
}

// LogoutToken signs a back-channel logout token. Override replaces claims, and
// a nil value removes one.
func (p *IDP) LogoutToken(override map[string]any) string {
	c := map[string]any{
		"iss": p.Issuer(), "aud": p.ClientID, "sub": p.Sub, "sid": p.SID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
		"jti":    "logout-1",
		"events": map[string]any{logoutEvent: map[string]any{}},
	}
	for k, v := range override {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return p.Sign(c)
}

// Sign produces a JWT with the provider's key.
func (p *IDP) Sign(claims map[string]any) string {
	s, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return s
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}
