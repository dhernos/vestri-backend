package auth

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	Redis *redis.Client
}

const (
	loginMaxAttempts         = 5
	loginAttemptTTL          = 10 * time.Minute
	loginBanTTL              = 1 * time.Hour
	twoFAMaxAttempts         = 5
	twoFAAttemptTTL          = 10 * time.Minute
	emailCooldown            = 60 * time.Second
	EmailCooldown            = emailCooldown
	verifyMaxAttempts        = 5
	verifyAttemptTTL         = 10 * time.Minute
	resetMaxAttempts         = 5
	resetAttemptTTL          = 15 * time.Minute
	registerMaxAttemptsIP    = 10
	registerAttemptTTLIP     = 30 * time.Minute
	registerMaxAttemptsEmail = 3
	registerAttemptTTLEmail  = 30 * time.Minute
)

func (r *RateLimiter) loginAttemptKey(ip string) string {
	return "login_attempts:" + ip
}

func (r *RateLimiter) loginBanKey(ip string) string {
	return "login_ban:" + ip
}

func (r *RateLimiter) twoFAKey(userID string) string {
	return "2fa_attempts:" + userID
}

func (r *RateLimiter) verifyAttemptKey(email string) string {
	return "verify_attempts:" + strings.ToLower(email)
}

func (r *RateLimiter) resetAttemptEmailKey(email string) string {
	if email == "" {
		return ""
	}
	return "reset_attempts:" + strings.ToLower(email)
}

func (r *RateLimiter) resetAttemptIPKey(ip string) string {
	if ip == "" {
		return ""
	}
	return "reset_attempts_ip:" + ip
}

func (r *RateLimiter) registerAttemptIPKey(ip string) string {
	if ip == "" {
		return ""
	}
	return "register_attempts_ip:" + ip
}

func (r *RateLimiter) registerAttemptEmailKey(email string) string {
	if email == "" {
		return ""
	}
	return "register_attempts_email:" + strings.ToLower(email)
}

func (r *RateLimiter) IsIPBanned(ctx context.Context, ip string) bool {
	exists, _ := r.Redis.Exists(ctx, r.loginBanKey(ip)).Result()
	return exists == 1
}

func (r *RateLimiter) RegisterLoginFailure(ctx context.Context, ip string) error {
	key := r.loginAttemptKey(ip)

	attempts, err := r.Redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	if attempts == 1 {
		r.Redis.Expire(ctx, key, loginAttemptTTL)
	}
	if attempts >= loginMaxAttempts {
		r.Redis.Set(ctx, r.loginBanKey(ip), "1", loginBanTTL)
		r.Redis.Expire(ctx, key, loginBanTTL)
	}
	return nil
}

func (r *RateLimiter) ResetLogin(ctx context.Context, ip string) {
	r.Redis.Del(ctx, r.loginAttemptKey(ip))
}

func (r *RateLimiter) Register2FAFailure(ctx context.Context, userID string) (bool, error) {
	key := r.twoFAKey(userID)
	attempts, err := r.Redis.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if attempts == 1 {
		r.Redis.Expire(ctx, key, twoFAAttemptTTL)
	}
	return attempts >= twoFAMaxAttempts, nil
}

func (r *RateLimiter) Reset2FA(ctx context.Context, userID string) {
	r.Redis.Del(ctx, r.twoFAKey(userID))
}

func (r *RateLimiter) RegisterVerifyAttempt(ctx context.Context, email string) (bool, time.Duration, error) {
	key := r.verifyAttemptKey(email)

	attempts, err := r.Redis.Incr(ctx, key).Result()
	if err != nil {
		return false, 0, err
	}
	if attempts == 1 {
		r.Redis.Expire(ctx, key, verifyAttemptTTL)
	}
	ttl, _ := r.Redis.TTL(ctx, key).Result()
	return attempts >= verifyMaxAttempts, ttl, nil
}

func (r *RateLimiter) ResetVerify(ctx context.Context, email string) {
	r.Redis.Del(ctx, r.verifyAttemptKey(email))
}

func (r *RateLimiter) RegisterResetAttempt(ctx context.Context, email, ip string) (bool, time.Duration, error) {
	keys := []string{r.resetAttemptEmailKey(email), r.resetAttemptIPKey(ip)}
	locked := false
	var ttlMax time.Duration

	for _, key := range keys {
		if key == "" {
			continue
		}
		attempts, err := r.Redis.Incr(ctx, key).Result()
		if err != nil {
			return false, 0, err
		}
		if attempts == 1 {
			r.Redis.Expire(ctx, key, resetAttemptTTL)
		}
		if attempts >= resetMaxAttempts {
			locked = true
		}
		if ttl, _ := r.Redis.TTL(ctx, key).Result(); ttl > ttlMax {
			ttlMax = ttl
		}
	}

	return locked, ttlMax, nil
}

func (r *RateLimiter) RegisterRegisterAttempt(ctx context.Context, email, ip string) (bool, time.Duration, error) {
	keys := []struct {
		key       string
		max       int64
		expiryTTL time.Duration
	}{
		{r.registerAttemptIPKey(ip), int64(registerMaxAttemptsIP), registerAttemptTTLIP},
		{r.registerAttemptEmailKey(email), int64(registerMaxAttemptsEmail), registerAttemptTTLEmail},
	}

	locked := false
	var ttlMax time.Duration

	for _, k := range keys {
		if k.key == "" {
			continue
		}
		attempts, err := r.Redis.Incr(ctx, k.key).Result()
		if err != nil {
			return false, 0, err
		}
		if attempts == 1 {
			r.Redis.Expire(ctx, k.key, k.expiryTTL)
		}
		if attempts >= k.max {
			locked = true
		}
		if ttl, _ := r.Redis.TTL(ctx, k.key).Result(); ttl > ttlMax {
			ttlMax = ttl
		}
	}

	return locked, ttlMax, nil
}

func (r *RateLimiter) CooldownTTL(ctx context.Context, key string) time.Duration {
	ttl, err := r.Redis.TTL(ctx, key).Result()
	if err != nil {
		return 0
	}
	return ttl
}

func (r *RateLimiter) SetCooldown(ctx context.Context, key string, ttl time.Duration) {
	r.Redis.Set(ctx, key, "1", ttl)
}
