package routes

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"time"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/db"
	"yas-web-backend/internal/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	upperRegex   = regexp.MustCompile(`[A-Z]`)
	lowerRegex   = regexp.MustCompile(`[a-z]`)
	numberRegex  = regexp.MustCompile(`[0-9]`)
	specialRegex = regexp.MustCompile(`[^A-Za-z0-9]`)
)

func AuthRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/signup", handleSignup)
	r.Post("/login", handleLogin)
	return r
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func signToken(userID, username string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub":      userID,
		"username": username,
		"iat":      now.Unix(),
		"exp":      now.Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(config.App.JWTSecret))
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	var body authRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "잘못된 요청입니다"})
		return
	}

	if len(body.Password) < 10 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "비밀번호는 최소 10자 이상이어야 합니다"})
		return
	}
	hasUpper := upperRegex.MatchString(body.Password)
	hasLower := lowerRegex.MatchString(body.Password)
	hasNumber := numberRegex.MatchString(body.Password)
	hasSpecial := specialRegex.MatchString(body.Password)
	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"message": "비밀번호가 약합니다: 대문자, 소문자, 숫자, 특수문자를 포함해주세요",
		})
		return
	}
	if len(body.Username) < 3 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "잘못된 요청입니다"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		log.Printf("Signup hash failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "회원가입에 실패했습니다"})
		return
	}

	user, err := db.CreateUser(body.Username, string(hash))
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			middleware.WriteJSON(w, http.StatusConflict, map[string]string{"message": "이미 존재하는 사용자입니다"})
			return
		}
		log.Printf("Signup failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "회원가입에 실패했습니다"})
		return
	}

	middleware.WriteJSON(w, http.StatusCreated, map[string]string{
		"id":       user.ID,
		"username": user.Username,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body authRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" || body.Password == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "잘못된 요청입니다"})
		return
	}

	user, err := db.GetUserByUsername(body.Username)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "아이디 또는 비밀번호가 올바르지 않습니다"})
			return
		}
		log.Printf("Login failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "로그인에 실패했습니다"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "아이디 또는 비밀번호가 올바르지 않습니다"})
		return
	}

	token, err := signToken(user.ID, user.Username)
	if err != nil {
		log.Printf("Token sign failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "로그인에 실패했습니다"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
		},
	})
}
