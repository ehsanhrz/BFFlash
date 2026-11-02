// Package cache is a per-instance LRU of upstream responses.
package cache

import (
	"container/list"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// MaxBody is the largest response worth keeping.
	MaxBody    = 1 << 20
	maxEntries = 10000
)

// Entry is a stored response.
type Entry struct {
	Status  int
	Header  http.Header
	Body    []byte
	Stored  bool // false means it belongs to the caller who fetched it
	expires time.Time
}

type item struct {
	key   string
	entry *Entry
}

// Cache evicts least recently used entries past maxEntries.
type Cache struct {
	mu      sync.Mutex
	lru     *list.List
	items   map[string]*list.Element
	flight  singleflight.Group
	now     func() time.Time
	maxSize int
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{lru: list.New(), items: map[string]*list.Element{}, now: time.Now, maxSize: maxEntries}
}

// Get returns a live entry.
func (c *Cache) Get(key string) (*Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*item).entry
	if !c.now().Before(e.expires) {
		c.remove(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return e, true
}

// Put stores an entry for ttl.
func (c *Cache) Put(key string, e *Entry, ttl time.Duration) {
	e.expires = c.now().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*item).entry = e
		c.lru.MoveToFront(el)
		return
	}
	c.items[key] = c.lru.PushFront(&item{key: key, entry: e})
	for c.lru.Len() > c.maxSize {
		c.remove(c.lru.Back())
	}
}

func (c *Cache) remove(el *list.Element) {
	c.lru.Remove(el)
	delete(c.items, el.Value.(*item).key)
}

// Do runs fill once for concurrent callers of the same key, so a cold entry
// costs the upstream one request.
func (c *Cache) Do(key string, fill func() (*Entry, error)) (*Entry, error) {
	v, err, _ := c.flight.Do(key, func() (any, error) { return fill() })
	if err != nil {
		return nil, err
	}
	return v.(*Entry), nil
}

// Storable reports whether a response may be kept. Anything marked private,
// and anything setting a cookie, belongs to one user alone.
func Storable(status int, h http.Header) bool {
	if status != http.StatusOK {
		return false
	}
	if h.Get("Set-Cookie") != "" || strings.Contains(h.Get("Vary"), "*") {
		return false
	}
	cc := strings.ToLower(strings.Join(h.Values("Cache-Control"), ","))
	return !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private")
}
