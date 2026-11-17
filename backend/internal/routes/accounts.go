package routes

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"yas-web-backend/internal/db"
	"yas-web-backend/internal/middleware"
	"yas-web-backend/internal/models"
	"yas-web-backend/internal/webauthn"

	"github.com/go-chi/chi/v5"
)

func AccountsRouter() http.Handler {
	r := chi.NewRouter()
	r.With(middleware.RequireAuth).Post("/", handleUpsertAccount)
	r.With(middleware.RequireAuth).Get("/me/vault", handleGetMyVault)
	r.With(middleware.RequireAuth).Post("/me/vault", handleGetMyVault)
	r.Get("/username/{username}", handleGetAccountByUsername)
	return r
}

func isBase64(str string) bool {
	cleaned := strings.Join(strings.Fields(str), "")
	if cleaned == "" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return false
	}
	return base64.StdEncoding.EncodeToString(decoded) == cleaned
}

func isBase64Length(str string, expected int) bool {
	cleaned := strings.Join(strings.Fields(str), "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return false
	}
	return len(decoded) == expected
}

func isBase64MinLength(str string, minExpected int) bool {
	cleaned := strings.Join(strings.Fields(str), "")
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return false
	}
	return len(decoded) >= minExpected
}

func validateAccountPayload(p models.AccountPayload) error {
	if len(p.Username) < 3 {
		return errors.New("username must be at least 3 characters")
	}
	if len(p.PublicKey) < 1 {
		return errors.New("publicKey is required")
	}
	if p.EncryptedPrivateKey.CipherText == "" || !isBase64(p.EncryptedPrivateKey.CipherText) {
		return errors.New("cipherText must be base64")
	}
	if p.EncryptedPrivateKey.IV == "" || !isBase64(p.EncryptedPrivateKey.IV) || !isBase64Length(p.EncryptedPrivateKey.IV, 12) {
		return errors.New("iv must be base64 12-byte (AES-GCM)")
	}
	if p.EncryptedPrivateKey.AuthTag != "" && !isBase64(p.EncryptedPrivateKey.AuthTag) {
		return errors.New("authTag must be base64")
	}
	if p.Kdf.Salt == "" || !isBase64(p.Kdf.Salt) || !isBase64MinLength(p.Kdf.Salt, 16) {
		return errors.New("salt must be base64 (at least 16 bytes)")
	}
	switch p.Kdf.Algorithm {
	case "arg2st", "arg2st-prf":
		if p.Kdf.Iterations == nil || *p.Kdf.Iterations < 3 {
			return errors.New("arg2st requires iterations >= 3")
		}
		if p.Kdf.MemoryCost == nil || *p.Kdf.MemoryCost < 65536 {
			return errors.New("arg2st requires memoryCost >= 65536")
		}
		if p.Kdf.Parallelism == nil || *p.Kdf.Parallelism < 1 {
			return errors.New("arg2st requires parallelism >= 1")
		}
	default:
		return errors.New("unsupported or weak kdf algorithm (must be arg2st or arg2st-prf)")
	}
	if p.Kdf.KeyLength == nil || *p.Kdf.KeyLength != 32 {
		return errors.New("keyLength must be 32")
	}
	return nil
}

func handleUpsertAccount(w http.ResponseWriter, r *http.Request) {
	var payload models.AccountPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}

	if err := validateAccountPayload(payload); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"message": "Invalid payload",
			"error":   err.Error(),
		})
		return
	}

	requester := middleware.GetUser(r)
	if requester == nil || requester.Username == "" || requester.Username != payload.Username {
		middleware.WriteJSON(w, http.StatusForbidden, map[string]string{"message": "Username mismatch"})
		return
	}

	doc, upserted, err := db.UpsertAccount(payload)
	if err != nil {
		log.Printf("Failed to store account: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to store account"})
		return
	}

	status := http.StatusOK
	if upserted {
		status = http.StatusCreated
	}
	middleware.WriteJSON(w, status, map[string]any{
		"id":        doc.ID,
		"createdAt": doc.CreatedAt,
		"updatedAt": doc.UpdatedAt,
		"upserted":  upserted,
	})
}

// handleGetAccountByUsername returns ONLY public account metadata (never encryptedPrivateKey or kdf).
func handleGetAccountByUsername(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	acc, err := db.GetAccountByUsername(username)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "Not found"})
			return
		}
		log.Printf("Lookup failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to fetch account"})
		return
	}
	middleware.WriteJSON(w, http.StatusOK, models.PublicAccount{
		ID:            acc.ID,
		Username:      acc.Username,
		PublicKey:     acc.PublicKey,
		HasPrivateKey: acc.EncryptedPrivateKey.CipherText != "",
		Notes:         acc.Notes,
		CreatedAt:     acc.CreatedAt,
		UpdatedAt:     acc.UpdatedAt,
	})
}

// handleGetMyVault returns the authenticated user's encrypted private key blob.
// ID/Password session authentication (RequireAuth) grants access to the encrypted private key blob;
// if an optional single-use verificationToken is provided, it is also verified and consumed.
func handleGetMyVault(w http.ResponseWriter, r *http.Request) {
	requester := middleware.GetUser(r)
	if requester == nil || requester.Sub == "" || requester.Username == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "로그인이 필요합니다"})
		return
	}

	var body struct {
		VerificationToken string `json:"verificationToken"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	verToken := strings.TrimSpace(body.VerificationToken)
	if verToken == "" {
		verToken = strings.TrimSpace(r.Header.Get("X-Verification-Token"))
	}

	if verToken != "" {
		if err := webauthn.VerifyAndConsumeVerificationToken(verToken, requester.Sub); err != nil {
			log.Printf("[Vault] Invalid verification token for user %s: %v", requester.Username, err)
			middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{
				"message": "인증 토큰이 유효하지 않거나 이미 사용되었습니다",
			})
			return
		}
	}

	acc, err := db.GetAccountByUsername(requester.Username)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "저장된 키가 없습니다"})
			return
		}
		log.Printf("Vault lookup failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "키 정보를 불러오지 못했습니다"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, models.AccountVaultResponse{
		Username:            acc.Username,
		PublicKey:           acc.PublicKey,
		EncryptedPrivateKey: acc.EncryptedPrivateKey,
		Kdf:                 acc.Kdf,
	})
}
