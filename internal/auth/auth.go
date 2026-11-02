// Package auth runs the OIDC flows and owns every token. The browser only ever
// holds an opaque session cookie.
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"bfflash/internal/config"
	"bfflash/internal/session"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/singleflight"
)

const (
	cookieName      = "__Host-bfflash"
	loginCookieName = "__Host-bfflash-login"
	loginTTL        = 10 * time.Minute
	refreshMargin   = 30 * time.Second
	networkTimeout  = 8 * time.Second
	backchannelSkew = 5 * time.Minute
	logoutEvent     = "http://schemas.openid.net/event/backchannel-logout"
)

// ErrSessionEnded means the provider refused a refresh, so the user must log in again.
var ErrSessionEnded = errors.New("session ended")

// Options configures a Service.
type Options struct {
	OIDC       config.OIDC
	Session    config.Session
	PublicURL  string
	BasePath   string
	CSRFHeader string
	Store      session.Store
	Sealer     *session.Sealer
	Log        *slog.Logger
	HTTP       *http.Client
}

// Service is the login and token authority.
type Service struct {
	opt      Options
	idle     time.Duration
	absolute time.Duration
	client   *http.Client
	flight   singleflight.Group

	mu       sync.Mutex
	provider *oidc.Provider
	clientTS oauth2.TokenSource
}

// New builds a Service. The provider is discovered on first use, so an identity
// provider that is briefly down costs a failed readiness probe, not a crash.
func New(opt Options) *Service {
	client := opt.HTTP
	if client == nil {
		client = &http.Client{Timeout: networkTimeout}
	}
	return &Service{
		opt:      opt,
		idle:     time.Duration(opt.Session.IdleTTL),
		absolute: time.Duration(opt.Session.AbsoluteTTL),
		client:   client,
	}
}

func (s *Service) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, s.client), s.client)
}

func (s *Service) discover(ctx context.Context) (*oidc.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	p, err := oidc.NewProvider(s.ctx(context.WithoutCancel(ctx)), s.opt.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", s.opt.OIDC.Issuer, err)
	}
	s.provider = p
	return p, nil
}

// Ready reports whether the provider is reachable.
func (s *Service) Ready(ctx context.Context) error {
	_, err := s.discover(ctx)
	return err
}

func (s *Service) oauth(r *http.Request, p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.opt.OIDC.ClientID,
		ClientSecret: s.opt.OIDC.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  s.publicURL(r) + s.opt.BasePath + "/callback",
		Scopes:       s.opt.OIDC.Scopes,
	}
}

// publicURL is the configured URL, or else whatever the request came in on.
// The provider checks redirect URIs against its allow list either way.
func (s *Service) publicURL(r *http.Request) string {
	if s.opt.PublicURL != "" {
		return strings.TrimRight(s.opt.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// Session returns the request's live session, or nil.
func (s *Service) Session(r *http.Request) (*session.Session, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, nil
	}
	sess, err := s.opt.Store.Get(r.Context(), c.Value)
	if err != nil || sess == nil {
		return nil, err
	}
	remaining := s.absolute - time.Since(sess.CreatedAt)
	if remaining <= 0 {
		s.opt.Store.Delete(r.Context(), sess.ID)
		return nil, nil
	}
	if err := s.opt.Store.Touch(r.Context(), sess.ID, min(s.idle, remaining)); err != nil {
		s.opt.Log.Warn("session touch failed", "err", err)
	}
	return sess, nil
}

// Token resolves what to send upstream for a token mode. An empty result means
// send nothing. The caller has already rejected a missing session where needed.
func (s *Service) Token(ctx context.Context, sess *session.Session, mode string) (string, error) {
	switch mode {
	case config.TokenNone:
		return "", nil
	case config.TokenClient:
		return s.clientToken(ctx)
	case config.TokenUserOrClient:
		if sess == nil {
			return s.clientToken(ctx)
		}
	case config.TokenUserOrNone:
		if sess == nil {
			return "", nil
		}
	}
	if sess == nil {
		return "", ErrSessionEnded
	}
	return s.userToken(ctx, sess)
}

func (s *Service) userToken(ctx context.Context, sess *session.Session) (string, error) {
	if sess.Expiry.IsZero() || time.Until(sess.Expiry) > refreshMargin {
		return sess.AccessToken, nil
	}
	if sess.RefreshToken == "" {
		if time.Now().Before(sess.Expiry) {
			return sess.AccessToken, nil
		}
		s.opt.Store.Delete(ctx, sess.ID)
		return "", ErrSessionEnded
	}
	// Refresh outlives the first caller, because the others are waiting on it.
	v, err, _ := s.flight.Do(sess.ID, func() (any, error) {
		return s.refresh(s.ctx(context.WithoutCancel(ctx)), sess.ID)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (s *Service) refresh(ctx context.Context, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	unlock, err := s.opt.Store.Lock(ctx, id)
	if err != nil {
		return "", err
	}
	defer unlock()

	// Another replica may have refreshed while this one queued for the lock.
	sess, err := s.opt.Store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if sess == nil {
		return "", ErrSessionEnded
	}
	if time.Until(sess.Expiry) > refreshMargin {
		return sess.AccessToken, nil
	}

	p, err := s.discover(ctx)
	if err != nil {
		return "", err
	}
	cfg := &oauth2.Config{ClientID: s.opt.OIDC.ClientID, ClientSecret: s.opt.OIDC.ClientSecret, Endpoint: p.Endpoint()}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: sess.RefreshToken, Expiry: time.Unix(1, 0)}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && re.Response.StatusCode < 500 {
			s.opt.Store.Delete(ctx, id)
			return "", ErrSessionEnded
		}
		return "", fmt.Errorf("refresh token: %w", err)
	}
	sess.AccessToken = tok.AccessToken
	sess.Expiry = tok.Expiry
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	if idt, ok := tok.Extra("id_token").(string); ok && idt != "" {
		sess.IDToken = idt
	}
	remaining := s.absolute - time.Since(sess.CreatedAt)
	if err := s.opt.Store.Put(ctx, sess, min(s.idle, remaining)); err != nil {
		return "", err
	}
	return sess.AccessToken, nil
}

func (s *Service) clientToken(ctx context.Context) (string, error) {
	p, err := s.discover(ctx)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	if s.clientTS == nil {
		cfg := clientcredentials.Config{
			ClientID:     s.opt.OIDC.ClientID,
			ClientSecret: s.opt.OIDC.ClientSecret,
			TokenURL:     p.Endpoint().TokenURL,
			Scopes:       s.opt.OIDC.ClientScopes,
		}
		s.clientTS = cfg.TokenSource(s.ctx(context.Background()))
	}
	ts := s.clientTS
	s.mu.Unlock()
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("client credentials: %w", err)
	}
	return tok.AccessToken, nil
}

// Handler serves the management endpoints. It reports false for any path it
// doesn't own.
func (s *Service) Handler(w http.ResponseWriter, r *http.Request) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, s.opt.BasePath+"/")
	if !ok {
		return false
	}
	switch rest {
	case "login":
		s.login(w, r)
	case "callback":
		s.callback(w, r)
	case "user":
		s.user(w, r)
	case "logout":
		s.logout(w, r)
	case "backchannel-logout":
		s.backchannelLogout(w, r)
	default:
		return false
	}
	return true
}

type loginState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Return   string    `json:"r"`
	Expires  time.Time `json:"e"`
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p, err := s.discover(r.Context())
	if err != nil {
		s.opt.Log.Error("login failed", "err", err)
		http.Error(w, "identity provider unavailable", http.StatusServiceUnavailable)
		return
	}
	st := loginState{
		State:    session.NewID(),
		Nonce:    session.NewID(),
		Verifier: oauth2.GenerateVerifier(),
		Return:   safeReturn(r.URL.Query().Get("returnUrl")),
		Expires:  time.Now().Add(loginTTL),
	}
	plain, _ := json.Marshal(st)
	sealed := s.opt.Sealer.Seal(plain, []byte(loginCookieName))
	setCookie(w, loginCookieName, base64.RawURLEncoding.EncodeToString(sealed), int(loginTTL.Seconds()))
	url := s.oauth(r, p).AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	st, err := s.readLoginCookie(r)
	if err != nil {
		http.Error(w, "login expired, please try again", http.StatusBadRequest)
		return
	}
	setCookie(w, loginCookieName, "", -1)
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	if e := q.Get("error"); e != "" {
		s.opt.Log.Warn("provider refused login", "error", e)
		http.Error(w, "login was refused", http.StatusForbidden)
		return
	}
	ctx := s.ctx(r.Context())
	p, err := s.discover(ctx)
	if err != nil {
		http.Error(w, "identity provider unavailable", http.StatusServiceUnavailable)
		return
	}
	tok, err := s.oauth(r, p).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		s.opt.Log.Warn("code exchange failed", "err", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier(&oidc.Config{ClientID: s.opt.OIDC.ClientID}).Verify(ctx, rawID)
	if err != nil {
		s.opt.Log.Warn("id token rejected", "err", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	sid, _ := claims["sid"].(string)

	// A fresh ID on every login: a value planted before login is worthless after it.
	if old, err := r.Cookie(cookieName); err == nil {
		s.opt.Store.Delete(ctx, old.Value)
	}
	sess := &session.Session{
		ID:           session.NewID(),
		Sub:          idt.Subject,
		SID:          sid,
		Claims:       publicClaims(claims),
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      rawID,
		Expiry:       tok.Expiry,
		CreatedAt:    time.Now(),
		LogoutToken:  session.NewID(),
	}
	if err := s.opt.Store.Put(ctx, sess, min(s.idle, s.absolute)); err != nil {
		s.opt.Log.Error("session store failed", "err", err)
		http.Error(w, "login failed", http.StatusServiceUnavailable)
		return
	}
	setCookie(w, cookieName, sess.ID, 0)
	http.Redirect(w, r, st.Return, http.StatusFound)
}

func (s *Service) readLoginCookie(r *http.Request) (*loginState, error) {
	c, err := r.Cookie(loginCookieName)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	plain, err := s.opt.Sealer.Open(sealed, []byte(loginCookieName))
	if err != nil {
		return nil, err
	}
	st := &loginState{}
	if err := json.Unmarshal(plain, st); err != nil {
		return nil, err
	}
	if time.Now().After(st.Expires) {
		return nil, errors.New("login state expired")
	}
	return st, nil
}

// HasCSRFHeader is the anti-forgery check. The value is irrelevant: a custom
// header can't be sent cross-origin without passing a CORS preflight.
func (s *Service) HasCSRFHeader(r *http.Request) bool {
	return r.Header.Get(s.opt.CSRFHeader) != ""
}

func (s *Service) user(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.HasCSRFHeader(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sess, err := s.Session(r)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if sess == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":        sess.Sub,
		"claims":     sess.Claims,
		"logout_url": s.opt.BasePath + "/logout?token=" + sess.LogoutToken,
	})
}

// logout accepts a POST with the CSRF header, answered with JSON for fetch, or
// a GET carrying the session's logout token, answered with a redirect. Either
// way a third-party page can't sign the user out.
func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	sess, err := s.Session(r)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPost:
		if !s.HasCSRFHeader(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		if sess == nil || subtle.ConstantTimeCompare([]byte(token), []byte(sess.LogoutToken)) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	target := safeReturn(r.URL.Query().Get("returnUrl"))
	if sess != nil {
		if err := s.opt.Store.Delete(r.Context(), sess.ID); err != nil {
			s.opt.Log.Error("session delete failed", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		target = s.endSessionURL(r, sess, target)
	}
	setCookie(w, cookieName, "", -1)
	if r.Method == http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"redirect": target})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Service) endSessionURL(r *http.Request, sess *session.Session, returnTo string) string {
	p, err := s.discover(r.Context())
	if err != nil {
		return returnTo
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&meta); err != nil || meta.EndSession == "" {
		return returnTo
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil {
		return returnTo
	}
	q := u.Query()
	q.Set("client_id", s.opt.OIDC.ClientID)
	q.Set("id_token_hint", sess.IDToken)
	q.Set("post_logout_redirect_uri", s.publicURL(r)+returnTo)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Service) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx := s.ctx(r.Context())
	p, err := s.discover(ctx)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	sub, sid, err := s.verifyLogoutToken(ctx, p, r.PostFormValue("logout_token"))
	if err != nil {
		s.opt.Log.Warn("back-channel logout rejected", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n, err := s.opt.Store.DeleteMatching(ctx, sub, sid)
	if err != nil {
		s.opt.Log.Error("back-channel logout failed", "err", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.opt.Log.Info("back-channel logout", "sessions", n)
}

func (s *Service) verifyLogoutToken(ctx context.Context, p *oidc.Provider, raw string) (sub, sid string, err error) {
	// The signature, iss, aud and exp checks all come from the ID token verifier.
	tok, err := p.Verifier(&oidc.Config{ClientID: s.opt.OIDC.ClientID}).Verify(ctx, raw)
	if err != nil {
		return "", "", err
	}
	var c struct {
		SID    string                     `json:"sid"`
		Nonce  *string                    `json:"nonce"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := tok.Claims(&c); err != nil {
		return "", "", err
	}
	if _, ok := c.Events[logoutEvent]; !ok {
		return "", "", errors.New("logout event missing")
	}
	// A nonce marks an ID token, which must never work as a logout token.
	if c.Nonce != nil {
		return "", "", errors.New("logout token has a nonce")
	}
	if tok.Subject == "" && c.SID == "" {
		return "", "", errors.New("logout token has neither sub nor sid")
	}
	if age := time.Since(tok.IssuedAt); tok.IssuedAt.IsZero() || age > backchannelSkew || age < -backchannelSkew {
		return "", "", errors.New("logout token iat out of range")
	}
	return tok.Subject, c.SID, nil
}

// safeReturn accepts same-origin paths only, which closes the open redirect.
func safeReturn(s string) string {
	if s == "" || s[0] != '/' || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return s
}

// publicClaims drops protocol fields, leaving what describes the user.
func publicClaims(c map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		switch k {
		case "iss", "aud", "exp", "iat", "nbf", "jti", "nonce", "azp", "at_hash", "c_hash", "sid", "auth_time", "acr", "amr", "typ":
		default:
			out[k] = v
		}
	}
	return out
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
