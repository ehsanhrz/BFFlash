package session

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func sealer(t *testing.T) *Sealer {
	t.Helper()
	s, err := NewSealer("")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// contract runs against every Store.
func contract(t *testing.T, st Store) {
	ctx := context.Background()
	put := func(sub, sid string) *Session {
		s := &Session{ID: NewID(), Sub: sub, SID: sid, AccessToken: "at-" + sub, CreatedAt: time.Now()}
		if err := st.Put(ctx, s, time.Minute); err != nil {
			t.Fatal(err)
		}
		return s
	}
	alive := func(s *Session) bool {
		got, err := st.Get(ctx, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got != nil
	}

	t.Run("round trip", func(t *testing.T) {
		s := put("alice", "sid-1")
		got, err := st.Get(ctx, s.ID)
		if err != nil || got == nil {
			t.Fatalf("get = %v, %v", got, err)
		}
		if got.ID != s.ID || got.AccessToken != "at-alice" {
			t.Errorf("got = %+v", got)
		}
	})
	t.Run("unknown is nil", func(t *testing.T) {
		if got, err := st.Get(ctx, NewID()); got != nil || err != nil {
			t.Errorf("got = %v, %v", got, err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		s := put("bob", "")
		st.Delete(ctx, s.ID)
		if alive(s) {
			t.Error("session survived delete")
		}
	})
	t.Run("logout by sid leaves the other login", func(t *testing.T) {
		a, b := put("carol", "sid-a"), put("carol", "sid-b")
		if n, err := st.DeleteMatching(ctx, "", "sid-a"); n != 1 || err != nil {
			t.Fatalf("n = %d, %v", n, err)
		}
		if alive(a) || !alive(b) {
			t.Errorf("a = %v, b = %v", alive(a), alive(b))
		}
	})
	t.Run("logout by sub ends every login", func(t *testing.T) {
		a, b, other := put("dave", "sid-c"), put("dave", "sid-d"), put("erin", "sid-e")
		if n, err := st.DeleteMatching(ctx, "dave", ""); n != 2 || err != nil {
			t.Fatalf("n = %d, %v", n, err)
		}
		if alive(a) || alive(b) || !alive(other) {
			t.Error("wrong sessions removed")
		}
	})
	t.Run("sid with wrong sub removes nothing", func(t *testing.T) {
		a := put("frank", "sid-f")
		if n, err := st.DeleteMatching(ctx, "mallory", "sid-f"); n != 0 || err != nil {
			t.Fatalf("n = %d, %v", n, err)
		}
		if !alive(a) {
			t.Error("session removed")
		}
	})
	t.Run("empty matcher removes nothing", func(t *testing.T) {
		a := put("gina", "")
		if n, _ := st.DeleteMatching(ctx, "", ""); n != 0 || !alive(a) {
			t.Errorf("n = %d", n)
		}
	})
	t.Run("lock", func(t *testing.T) {
		unlock, err := st.Lock(ctx, "x")
		if err != nil {
			t.Fatal(err)
		}
		unlock()
	})
}

func TestMemory(t *testing.T) { contract(t, NewMemory(sealer(t))) }

// Set BFFLASH_TEST_REDIS=redis://localhost:6379/15 to run this.
func TestRedis(t *testing.T) {
	u := os.Getenv("BFFLASH_TEST_REDIS")
	if u == "" {
		t.Skip("BFFLASH_TEST_REDIS not set")
	}
	r, err := NewRedis(u, sealer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.prefix = "bfflash-test-" + NewID()[:8] + ":"
	contract(t, r)

	t.Run("expiry and touch", func(t *testing.T) {
		ctx := context.Background()
		s := &Session{ID: NewID(), Sub: "x"}
		r.Put(ctx, s, 150*time.Millisecond)
		r.Touch(ctx, s.ID, time.Minute)
		time.Sleep(300 * time.Millisecond)
		if got, _ := r.Get(ctx, s.ID); got == nil {
			t.Error("touch did not extend expiry")
		}
	})
	t.Run("lock excludes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		unlock, err := r.Lock(context.Background(), "y")
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		if _, err := r.Lock(ctx, "y"); err == nil {
			t.Error("second lock succeeded")
		}
	})
}

func TestMemoryExpiryTouchAndSweep(t *testing.T) {
	m := NewMemory(sealer(t))
	now := time.Now()
	m.now = func() time.Time { return now }
	ctx := context.Background()
	s := &Session{ID: NewID()}
	m.Put(ctx, s, time.Minute)

	now = now.Add(50 * time.Second)
	m.Touch(ctx, s.ID, time.Minute)
	now = now.Add(50 * time.Second)
	if got, _ := m.Get(ctx, s.ID); got == nil {
		t.Fatal("touch did not extend expiry")
	}

	now = now.Add(2 * time.Minute)
	m.Sweep(ctx)
	if m.Len() != 0 {
		t.Errorf("len = %d after sweep", m.Len())
	}
}

func TestTokensAreSealedAtRest(t *testing.T) {
	m := NewMemory(sealer(t))
	s := &Session{ID: NewID(), AccessToken: "super-secret-token"}
	m.Put(context.Background(), s, time.Minute)
	for key, e := range m.entries {
		if strings.Contains(key, s.ID) {
			t.Error("raw session ID used as the store key")
		}
		if strings.Contains(string(e.sealed), "super-secret-token") {
			t.Error("token readable in the store")
		}
	}
}

func TestSealerRejectsTamperingAndWrongContext(t *testing.T) {
	s := sealer(t)
	sealed := s.Seal([]byte("hello"), []byte("a"))
	if _, err := s.Open(sealed, []byte("b")); err == nil {
		t.Error("opened with the wrong aad")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := s.Open(sealed, []byte("a")); err == nil {
		t.Error("opened a tampered value")
	}
}
