package server

import (
	"context"
	"net/http"
	"time"

	"yourapp/internal/auth"
)

type ctxKey string

const sessionContextKey ctxKey = "session"

func (s *Server) requireSession(enforce2FA bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			sess, err := s.Sessions.Get(r.Context(), cookie.Value)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to read session")
				return
			}
			if sess == nil || sess.ExpiresAt.Before(time.Now()) {
				writeError(w, http.StatusUnauthorized, "Session expired")
				return
			}

			if enforce2FA && sess.TwoFactorEnabled && !sess.TwoFactorVerified {
				writeError(w, http.StatusForbidden, "Two Factor Verification required")
				return
			}

			ctx := context.WithValue(r.Context(), sessionContextKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *Server) requireRoles(roles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicAccess(roles) {
				next.ServeHTTP(w, r)
				return
			}

			sess := sessionFromContext(r.Context())
			if sess == nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			if !roleAllowed(roles, sess.Role) {
				writeError(w, http.StatusForbidden, "Forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func sessionFromContext(ctx context.Context) *auth.Session {
	if val, ok := ctx.Value(sessionContextKey).(*auth.Session); ok {
		return val
	}
	return nil
}
