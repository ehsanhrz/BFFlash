// Package limit is per-instance token bucket rate limiting.
package limit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const idleAfter = 10 * time.Minute

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// Limiter holds a bucket per key. It lives outside the compiled config, so a
// reload doesn't hand everyone a fresh allowance.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
	last    time.Time
}

// New returns an empty Limiter.
func New() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: time.Now}
}

// Allow spends one token from key's bucket. Rate and burst are read on each
// call, so a changed config applies to existing buckets.
func (l *Limiter) Allow(key string, r float64, burst int) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evict(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(rate.Limit(r), burst)}
		l.buckets[key] = b
	}
	b.seen = now
	b.lim.SetLimitAt(now, rate.Limit(r))
	b.lim.SetBurstAt(now, burst)
	return b.lim.AllowN(now, 1)
}

func (l *Limiter) evict(now time.Time) {
	if now.Sub(l.last) < time.Minute {
		return
	}
	l.last = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > idleAfter {
			delete(l.buckets, k)
		}
	}
}

// Len reports the buckets held.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
