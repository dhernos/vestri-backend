package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type AuditEvent struct {
	EventType string                 `json:"eventType"`
	UserID    string                 `json:"userId,omitempty"`
	IP        string                 `json:"ip"`
	UserAgent string                 `json:"userAgent"`
	Timestamp time.Time              `json:"timestamp"`
	Meta      map[string]interface{} `json:"meta,omitempty"`
}

type AuditLogger struct {
	Redis  *redis.Client
	MaxLen int64
}

func (a *AuditLogger) Log(ctx context.Context, e AuditEvent) error {
	e.Timestamp = time.Now().UTC()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}

	key := "audit"
	if e.UserID != "" {
		key = "audit:" + e.UserID
	}

	pipe := a.Redis.Pipeline()
	pipe.RPush(ctx, key, data)
	if a.MaxLen > 0 {
		pipe.LTrim(ctx, key, -a.MaxLen, -1)
	}

	_, err = pipe.Exec(ctx)
	return err
}
