package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"yas-web-backend/internal/config"

	"github.com/golang-jwt/jwt/v5"
)

type AuthPayload struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
}

type contextKey string

const userContextKey contextKey = "auth_user"

func GetUser(r *http.Request) *AuthPayload {
	val := r.Context().Value(userContextKey)
	if u, ok := val.(*AuthPayload); ok {
		return u
	}
	return nil
}

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func MaxBodyBytes(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" || !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			log.Println("[requireAuth] Missing or invalid Authorization header")
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
			return
		}

		tokenStr := strings.TrimSpace(header[len("bearer "):])
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(config.App.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			log.Printf("[requireAuth] Token verification failed: %v", err)
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Invalid token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Invalid token"})
			return
		}

		sub, _ := claims["sub"].(string)
		username, _ := claims["username"].(string)

		log.Printf("[requireAuth] Token verified successfully, sub: %s", sub)
		ctx := context.WithValue(r.Context(), userContextKey, &AuthPayload{
			Sub:      sub,
			Username: username,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
