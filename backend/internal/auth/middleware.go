package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const userContextKey contextKey = "sentracore_user"

func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

func JWTMiddleware(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if h == "" || !strings.HasPrefix(h, "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(h, "Bearer ")
			claims, err := svc.ParseToken(token)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			user := &User{
				ID:       claims.UserID,
				Username: claims.Username,
				Role:     claims.Role,
			}
			ctx := WithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(next http.HandlerFunc, roles ...Role) http.HandlerFunc {
	allowed := make(map[Role]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, ok := allowed[user.Role]; !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
