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

	"github.com/go-chi/chi/v5"
)

func AccountsRouter() http.Handler {
	r := chi.NewRouter()
	r.With(middleware.RequireAuth).Post("/", handleUpsertAccount)
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
	if p.Kdf.Salt == "" || !isBase64(p.Kdf.Salt) {
		return errors.New("salt must be base64")
	}
	switch p.Kdf.Algorithm {
	case "PBKDF2":
		if p.Kdf.Iterations == nil || *p.Kdf.Iterations <= 0 {
			return errors.New("PBKDF2 requires iterations")
		}
		if p.Kdf.Hash == "" {
			return errors.New("PBKDF2 requires hash")
		}
	default:
		return errors.New("invalid kdf algorithm")
	}
	if p.Kdf.KeyLength == nil || *p.Kdf.KeyLength <= 0 {
		return errors.New("keyLength is required")
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
	if requester != nil && requester.Username != "" && requester.Username != payload.Username {
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
	middleware.WriteJSON(w, http.StatusOK, acc)
}
