package auth

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Session struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"userId"`
	Role                string     `json:"role"`
	IP                  string     `json:"ip"`
	UserAgent           string     `json:"userAgent"`
	Location            string     `json:"location,omitempty"`
	ExpiresAt           time.Time  `json:"expiresAt"`
	LoginTime           time.Time  `json:"loginTime"`
	TwoFactorVerified   bool       `json:"twoFactorVerified"`
	TwoFactorVerifiedAt *time.Time `json:"twoFactorVerifiedAt,omitempty"`
	TwoFactorEnabled    bool       `json:"twoFactorEnabled"`
	TTLSeconds          int64      `json:"ttlSeconds"`
}

type SessionStore struct {
	Redis *redis.Client
}

func (s *SessionStore) Create(ctx context.Context, sess Session) error {
	key := "session:" + sess.ID

	data := map[string]interface{}{
		"userId":            sess.UserID,
		"role":              sess.Role,
		"ipAddress":         sess.IP,
		"userAgent":         sess.UserAgent,
		"expires":           sess.ExpiresAt.Unix(),
		"loginTime":         sess.LoginTime.Unix(),
		"twoFactorVerified": sess.TwoFactorVerified,
		"twoFactorEnabled":  sess.TwoFactorEnabled,
		"location":          sess.Location,
	}

	if sess.TwoFactorVerifiedAt != nil {
		data["twoFactorVerifiedAt"] = sess.TwoFactorVerifiedAt.Unix()
	}

	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Minute
	}

	pipe := s.Redis.TxPipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *SessionStore) Get(ctx context.Context, id string) (*Session, error) {
	key := "session:" + id
	vals, err := s.Redis.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, nil
	}

	expUnix, _ := strconv.ParseInt(vals["expires"], 10, 64)
	loginUnix, _ := strconv.ParseInt(vals["loginTime"], 10, 64)
	twoFactorVerifiedAtUnix, _ := strconv.ParseInt(vals["twoFactorVerifiedAt"], 10, 64)
	ttl, _ := s.Redis.TTL(ctx, key).Result()

	sess := &Session{
		ID:                id,
		UserID:            vals["userId"],
		Role:              vals["role"],
		IP:                vals["ipAddress"],
		UserAgent:         vals["userAgent"],
		Location:          vals["location"],
		ExpiresAt:         time.Unix(expUnix, 0),
		LoginTime:         time.Unix(loginUnix, 0),
		TwoFactorVerified: vals["twoFactorVerified"] == "1" || strings.ToLower(vals["twoFactorVerified"]) == "true",
		TwoFactorEnabled:  vals["twoFactorEnabled"] == "1" || strings.ToLower(vals["twoFactorEnabled"]) == "true",
		TTLSeconds:        int64(ttl.Seconds()),
	}

	if twoFactorVerifiedAtUnix > 0 {
		t := time.Unix(twoFactorVerifiedAtUnix, 0)
		sess.TwoFactorVerifiedAt = &t
	}

	if sess.ExpiresAt.Before(time.Now()) {
		_ = s.Delete(ctx, id)
		return nil, nil
	}

	return sess, nil
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	return s.Redis.Del(ctx, "session:"+id).Err()
}

func (s *SessionStore) DeleteByUser(ctx context.Context, userID string) error {
	sessions, err := s.ListForUser(ctx, userID)
	if err != nil {
		return err
	}
	pipe := s.Redis.TxPipeline()
	for _, sess := range sessions {
		pipe.Del(ctx, "session:"+sess.ID)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s *SessionStore) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	var sessions []Session
	iter := s.Redis.Scan(ctx, 0, "session:*", 100).Iterator()
	for iter.Next(ctx) {
		id := strings.TrimPrefix(iter.Val(), "session:")
		sess, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if sess != nil && sess.UserID == userID {
			sessions = append(sessions, *sess)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

func NewSessionID() string {
	return uuid.NewString()
}
