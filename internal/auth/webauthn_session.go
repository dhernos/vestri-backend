package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

type WebAuthnSessionStore struct {
	Redis *redis.Client
}

func (s *WebAuthnSessionStore) Save(ctx context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.Redis.Set(ctx, key, raw, ttl).Err()
}

func (s *WebAuthnSessionStore) Get(ctx context.Context, key string) (*webauthn.SessionData, error) {
	raw, err := s.Redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(raw, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

func (s *WebAuthnSessionStore) Delete(ctx context.Context, key string) {
	_ = s.Redis.Del(ctx, key).Err()
}
