package limit

import (
	"testing"
	"time"
)

func TestBurstRefillAndIsolation(t *testing.T) {
	l := New()
	now := time.Now()
	l.now = func() time.Time { return now }

	if !l.Allow("a", 1, 2) || !l.Allow("a", 1, 2) {
		t.Fatal("burst refused")
	}
	if l.Allow("a", 1, 2) {
		t.Fatal("over burst allowed")
	}
	if !l.Allow("b", 1, 2) {
		t.Fatal("keys share a bucket")
	}
	now = now.Add(time.Second)
	if !l.Allow("a", 1, 2) {
		t.Fatal("no refill")
	}
}

func TestIdleBucketsAreEvicted(t *testing.T) {
	l := New()
	now := time.Now()
	l.now = func() time.Time { return now }
	l.Allow("a", 1, 1)
	now = now.Add(idleAfter + 2*time.Minute)
	l.Allow("b", 1, 1)
	if l.Len() != 1 {
		t.Errorf("len = %d", l.Len())
	}
}
