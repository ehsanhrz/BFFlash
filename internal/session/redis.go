package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	lockTTL  = 10 * time.Second
	lockWait = 8 * time.Second
)

// Redis shares sessions between replicas and keeps them across restarts.
type Redis struct {
	rdb    *redis.Client
	sealer *Sealer
	prefix string
}

// NewRedis connects using a redis:// URL.
func NewRedis(rawURL string, sealer *Sealer) (*Redis, error) {
	opt, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("session.url: %w", err)
	}
	return &Redis{rdb: redis.NewClient(opt), sealer: sealer, prefix: "bfflash:"}, nil
}

func (r *Redis) sessKey(key string) string { return r.prefix + "s:" + key }
func (r *Redis) subKey(sub string) string  { return r.prefix + "sub:" + keyOf(sub) }
func (r *Redis) sidKey(sid string) string  { return r.prefix + "sid:" + keyOf(sid) }

func (r *Redis) Get(ctx context.Context, id string) (*Session, error) {
	key := keyOf(id)
	sealed, err := r.rdb.Get(ctx, r.sessKey(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := r.sealer.Open(sealed, []byte(key))
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

func (r *Redis) Put(ctx context.Context, s *Session, ttl time.Duration) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	key := keyOf(s.ID)
	pipe := r.rdb.TxPipeline()
	pipe.Set(ctx, r.sessKey(key), r.sealer.Seal(plain, []byte(key)), ttl)
	if s.Sub != "" {
		pipe.SAdd(ctx, r.subKey(s.Sub), key)
		pipe.Expire(ctx, r.subKey(s.Sub), 7*24*time.Hour)
	}
	if s.SID != "" {
		pipe.SAdd(ctx, r.sidKey(s.SID), key)
		pipe.Expire(ctx, r.sidKey(s.SID), 7*24*time.Hour)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (r *Redis) Touch(ctx context.Context, id string, ttl time.Duration) error {
	return r.rdb.Expire(ctx, r.sessKey(keyOf(id)), ttl).Err()
}

func (r *Redis) Delete(ctx context.Context, id string) error {
	return r.rdb.Del(ctx, r.sessKey(keyOf(id))).Err()
}

func (r *Redis) DeleteMatching(ctx context.Context, sub, sid string) (int, error) {
	var keys []string
	var err error
	switch {
	case sid != "":
		keys, err = r.rdb.SMembers(ctx, r.sidKey(sid)).Result()
	case sub != "":
		keys, err = r.rdb.SMembers(ctx, r.subKey(sub)).Result()
	}
	if err != nil {
		return 0, err
	}
	if sid != "" && sub != "" {
		keep, err := r.rdb.SMembers(ctx, r.subKey(sub)).Result()
		if err != nil {
			return 0, err
		}
		owned := make(map[string]bool, len(keep))
		for _, k := range keep {
			owned[k] = true
		}
		kept := keys[:0]
		for _, k := range keys {
			if owned[k] {
				kept = append(kept, k)
			}
		}
		keys = kept
	}
	n := 0
	for _, k := range keys {
		removed, err := r.rdb.Del(ctx, r.sessKey(k)).Result()
		if err != nil {
			return n, err
		}
		n += int(removed)
	}
	return n, nil
}

// Lock spins on a short-lived key, so a crashed holder blocks nobody for long.
func (r *Redis) Lock(ctx context.Context, id string) (func(), error) {
	key := r.prefix + "lock:" + keyOf(id)
	deadline := time.Now().Add(lockWait)
	for {
		ok, err := r.rdb.SetNX(ctx, key, 1, lockTTL).Result()
		if err != nil {
			return nil, err
		}
		if ok {
			return func() { r.rdb.Del(context.WithoutCancel(ctx), key) }, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for the session lock")
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Sweep has nothing to do: Redis expires keys itself.
func (r *Redis) Sweep(context.Context) error { return nil }

func (r *Redis) Close() error { return r.rdb.Close() }

// Ping checks connectivity for readiness.
func (r *Redis) Ping(ctx context.Context) error { return r.rdb.Ping(ctx).Err() }
