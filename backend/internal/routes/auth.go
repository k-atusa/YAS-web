package routes

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/db"
	"yas-web-backend/internal/middleware"
	"yas-web-backend/internal/webauthn"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

const (
	arg2stTime    uint32 = 3
	arg2stMemory  uint32 = 262144 // 256 MiB in KiB (matches USAG arg2st specification)
	arg2stThreads uint8  = 6
	arg2stHashLen uint32 = 64
	arg2stKeyLen  int    = 32
	arg2stSaltLen int    = 16
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
	r.With(middleware.RequireAuth).Post("/verify-password", handleVerifyPassword)
	r.With(middleware.RequireAuth).Post("/delete-account", handleDeleteAccount)
	return r
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func deriveArg2stStoreKey(password string, salt []byte, timeCost, memoryCost uint32, threads uint8) []byte {
	master := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, arg2stHashLen)
	mac := hmac.New(sha3.New512, master)
	mac.Write([]byte("PWHASH_ARG2ST"))
	sum := mac.Sum(nil)
	return sum[:arg2stKeyLen]
}

func hashPasswordArg2st(password string) (string, error) {
	salt := make([]byte, arg2stSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	storeKey := deriveArg2stStoreKey(password, salt, arg2stTime, arg2stMemory, arg2stThreads)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	keyB64 := base64.RawStdEncoding.EncodeToString(storeKey)
	return fmt.Sprintf("$arg2st$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, arg2stMemory, arg2stTime, arg2stThreads, saltB64, keyB64), nil
}

func verifyPasswordArg2st(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "arg2st" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false
	}
	if memory == 0 || timeCost == 0 || threads == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false
	}
	expectedKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expectedKey) != arg2stKeyLen {
		return false
	}
	actualKey := deriveArg2stStoreKey(password, salt, timeCost, memory, threads)
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1
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

	hash, err := hashPasswordArg2st(body.Password)
	if err != nil {
		log.Printf("Signup hash failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "회원가입에 실패했습니다"})
		return
	}

	user, err := db.CreateUser(body.Username, hash)
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

	if !verifyPasswordArg2st(body.Password, user.PasswordHash) {
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
		"r0Salt":     user.R0Salt,
		"hasPasskey": len(user.WebAuthnCredentials) > 0,
	})
}

func handleVerifyPassword(w http.ResponseWriter, r *http.Request) {
	reqUser := middleware.GetUser(r)
	if reqUser == nil || reqUser.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "로그인이 필요합니다"})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "비밀번호를 입력해주세요"})
		return
	}

	user, err := db.GetUserByID(reqUser.Sub)
	if err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "사용자 정보를 찾을 수 없습니다"})
		return
	}

	if !verifyPasswordArg2st(body.Password, user.PasswordHash) {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "비밀번호가 올바르지 않습니다"})
		return
	}

	token, expiresAt, err := webauthn.GenerateVerificationToken(user.ID, 60)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "인증 토큰 발급에 실패했습니다"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": expiresAt,
		"r0Salt":    user.R0Salt,
		"verified":  true,
	})
}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	reqUser := middleware.GetUser(r)
	if reqUser == nil || reqUser.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "로그인이 필요합니다"})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "비밀번호를 입력해주세요"})
		return
	}

	user, err := db.GetUserByID(reqUser.Sub)
	if err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "사용자 정보를 찾을 수 없습니다"})
		return
	}

	if !verifyPasswordArg2st(body.Password, user.PasswordHash) {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "비밀번호가 올바르지 않습니다"})
		return
	}

	if err := db.DeleteUserAndData(user.ID, user.Username); err != nil {
		log.Printf("Delete account failed for %s: %v", user.Username, err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "계정 탈퇴 처리에 실패했습니다"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "계정이 삭제되었습니다",
	})
}
