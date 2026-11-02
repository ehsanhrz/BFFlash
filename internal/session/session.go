// Package session stores login sessions on the server side. Tokens never leave
// this package's stores except through the auth package.
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Session is one logged-in browser.
type Session struct {
	ID           string         `json:"-"`
	Sub          string         `json:"sub"`
	SID          string         `json:"sid,omitempty"`
	Claims       map[string]any `json:"claims,omitempty"`
	AccessToken  string         `json:"access_token,omitempty"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	IDToken      string         `json:"id_token,omitempty"`
	Expiry       time.Time      `json:"expiry"`       // of the access token
	CreatedAt    time.Time      `json:"created_at"`   // bounds the absolute lifetime
	LogoutToken  string         `json:"logout_token"` // proves a GET logout is same-site
}

// Store persists sessions. Get returns nil, nil for an unknown ID.
type Store interface {
	Get(ctx context.Context, id string) (*Session, error)
	Put(ctx context.Context, s *Session, ttl time.Duration) error
	// Touch extends expiry without rewriting the session, so a request holding
	// an old copy can never undo a concurrent token refresh.
	Touch(ctx context.Context, id string, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
	// DeleteMatching removes sessions for a back-channel logout. A non-empty
	// sid narrows to that login; otherwise every session of sub goes.
	DeleteMatching(ctx context.Context, sub, sid string) (int, error)
	// Lock serializes token refresh for one session across replicas.
	Lock(ctx context.Context, id string) (unlock func(), err error)
	Sweep(ctx context.Context) error
	Close() error
}

// NewID returns an unguessable session identifier.
func NewID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// keyOf hides the live cookie value from anyone who can read the store.
func keyOf(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

// Sealer is AES-256-GCM over a key derived from the configured secret.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer. An empty secret picks a random key, which is fine
// for a single process that loses its sessions on restart anyway.
func NewSealer(secret string) (*Sealer, error) {
	var key [32]byte
	if secret == "" {
		rand.Read(key[:])
	} else {
		key = sha256.Sum256([]byte(secret))
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plain, binding it to aad.
func (s *Sealer) Seal(plain, aad []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return s.aead.Seal(nonce, nonce, plain, aad)
}

// Open reverses Seal.
func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value too short")
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, fmt.Errorf("open sealed value: %w", err)
	}
	return plain, nil
}
