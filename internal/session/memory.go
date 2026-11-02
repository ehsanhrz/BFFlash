package session

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

type memEntry struct {
	sealed  []byte
	sub     string
	sid     string
	expires time.Time
}

// Memory is the default store. Sessions die with the process.
type Memory struct {
	mu      sync.Mutex
	sealer  *Sealer
	entries map[string]*memEntry
	now     func() time.Time
}

// NewMemory returns an empty store.
func NewMemory(sealer *Sealer) *Memory {
	return &Memory{sealer: sealer, entries: map[string]*memEntry{}, now: time.Now}
}

func (m *Memory) Get(_ context.Context, id string) (*Session, error) {
	key := keyOf(id)
	m.mu.Lock()
	e, ok := m.entries[key]
	if ok && !m.now().Before(e.expires) {
		delete(m.entries, key)
		ok = false
	}
	m.mu.Unlock()
	if !ok {
		return nil, nil
	}
	plain, err := m.sealer.Open(e.sealed, []byte(key))
	if err != nil {
		return nil, err
	}
	s := &Session{}
	if err := json.Unmarshal(plain, s); err != nil {
		return nil, err
	}
	s.ID = id
	return s, nil
}

func (m *Memory) Put(_ context.Context, s *Session, ttl time.Duration) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	key := keyOf(s.ID)
	sealed := m.sealer.Seal(plain, []byte(key))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = &memEntry{sealed: sealed, sub: s.Sub, sid: s.SID, expires: m.now().Add(ttl)}
	return nil
}

func (m *Memory) Touch(_ context.Context, id string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[keyOf(id)]; ok {
		e.expires = m.now().Add(ttl)
	}
	return nil
}

func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, keyOf(id))
	return nil
}

func (m *Memory) DeleteMatching(_ context.Context, sub, sid string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for key, e := range m.entries {
		if matches(e.sub, e.sid, sub, sid) {
			delete(m.entries, key)
			n++
		}
	}
	return n, nil
}

func matches(sessSub, sessSID, sub, sid string) bool {
	if sid != "" {
		return sessSID == sid && (sub == "" || sessSub == sub)
	}
	return sub != "" && sessSub == sub
}

// Lock is a no-op: auth's singleflight already serializes within one process.
func (m *Memory) Lock(context.Context, string) (func(), error) {
	return func() {}, nil
}

func (m *Memory) Sweep(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for key, e := range m.entries {
		if !now.Before(e.expires) {
			delete(m.entries, key)
		}
	}
	return nil
}

func (m *Memory) Close() error { return nil }

// Len reports the entries held, expired ones included until swept.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
