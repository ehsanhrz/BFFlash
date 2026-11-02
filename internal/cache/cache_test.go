package cache

import (
	"net/http"
	"testing"
	"time"
)

func TestExpiry(t *testing.T) {
	c := New()
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put("k", &Entry{Status: 200}, time.Minute)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("miss before expiry")
	}
	now = now.Add(time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("hit after expiry")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New()
	c.maxSize = 2
	c.Put("a", &Entry{}, time.Minute)
	c.Put("b", &Entry{}, time.Minute)
	c.Get("a")
	c.Put("c", &Entry{}, time.Minute)
	if _, ok := c.Get("b"); ok {
		t.Error("b should be evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("a should survive")
	}
}

func TestStorable(t *testing.T) {
	h := func(k, v string) http.Header { return http.Header{k: {v}} }
	cases := []struct {
		status int
		header http.Header
		want   bool
	}{
		{200, http.Header{}, true},
		{200, h("Cache-Control", "max-age=60"), true},
		{200, h("Cache-Control", "no-store"), false},
		{200, h("Cache-Control", "Private, max-age=60"), false},
		{200, h("Set-Cookie", "a=b"), false},
		{404, http.Header{}, false},
		{500, http.Header{}, false},
	}
	for _, c := range cases {
		if got := Storable(c.status, c.header); got != c.want {
			t.Errorf("Storable(%d, %v) = %v", c.status, c.header, got)
		}
	}
}
