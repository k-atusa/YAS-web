package routes

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"yas-web-backend/internal/db"
	"yas-web-backend/internal/middleware"
	"yas-web-backend/internal/models"
	"yas-web-backend/internal/webauthn"

	"github.com/go-chi/chi/v5"
)

func WebAuthnRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequireAuth)
	r.Post("/register-options", handleRegisterOptions)
	r.Post("/register-verify", handleRegisterVerify)
	r.Post("/authenticate-options", handleAuthenticateOptions)
	r.Post("/authenticate-verify", handleAuthenticateVerify)
	return r
}

func handleRegisterOptions(w http.ResponseWriter, r *http.Request) {
	reqUser := middleware.GetUser(r)
	if reqUser == nil || reqUser.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	user, err := db.GetUserByID(reqUser.Sub)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "User not found"})
			return
		}
		log.Printf("WebAuthn register-options failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to generate registration options"})
		return
	}

	challenge := webauthn.GenerateChallenge()
	options := webauthn.GenerateRegistrationOptions(user.Username, user.ID, challenge)

	user.WebAuthnChallenge = challenge
	if err := db.SaveUser(user); err != nil {
		log.Printf("WebAuthn register-options save failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to generate registration options"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]any{"options": options})
}

func handleRegisterVerify(w http.ResponseWriter, r *http.Request) {
	reqUser := middleware.GetUser(r)
	if reqUser == nil || reqUser.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	var body struct {
		CredentialID string   `json:"credentialId"`
		PublicKey    string   `json:"publicKey"`
		Counter      *int     `json:"counter"`
		Transports   []string `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}
	if body.CredentialID == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "credentialId cannot be empty"})
		return
	}
	if body.PublicKey == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "publicKey cannot be empty"})
		return
	}
	if body.Counter == nil || *body.Counter < 0 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}

	if !webauthn.IsValidBase64(body.CredentialID) {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "credentialId must be valid base64"})
		return
	}
	if !webauthn.IsValidBase64(body.PublicKey) {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "publicKey must be valid base64"})
		return
	}

	user, err := db.GetUserByID(reqUser.Sub)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "User not found"})
			return
		}
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to verify credential"})
		return
	}

	for _, c := range user.WebAuthnCredentials {
		if c.ID == body.CredentialID {
			middleware.WriteJSON(w, http.StatusConflict, map[string]string{"message": "Credential already registered"})
			return
		}
	}

	log.Printf("[WebAuthn] Registering credential with initial counter: %d", *body.Counter)

	user.WebAuthnCredentials = append(user.WebAuthnCredentials, models.WebAuthnCredential{
		ID:         body.CredentialID,
		PublicKey:  body.PublicKey,
		Counter:    *body.Counter,
		Transports: body.Transports,
	})
	user.WebAuthnChallenge = ""

	if err := db.SaveUser(user); err != nil {
		log.Printf("WebAuthn register-verify failed: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to verify credential"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]string{"message": "Credential registered successfully"})
}

func handleAuthenticateOptions(w http.ResponseWriter, r *http.Request) {
	reqUser := middleware.GetUser(r)
	if reqUser == nil || reqUser.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	user, err := db.GetUserByID(reqUser.Sub)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "User not found"})
			return
		}
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to generate authentication options"})
		return
	}

	if len(user.WebAuthnCredentials) == 0 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "No WebAuthn credentials registered"})
		return
	}

	challenge := webauthn.GenerateChallenge()
	options := webauthn.GenerateAuthenticationOptions(challenge, user.WebAuthnCredentials)

	user.WebAuthnChallenge = challenge
	if err := db.SaveUser(user); err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to generate authentication options"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]any{"options": options})
}

func handleAuthenticateVerify(w http.ResponseWriter, r *http.Request) {
	reqUser := middleware.GetUser(r)
	if reqUser == nil || reqUser.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	var body struct {
		CredentialID string `json:"credentialId"`
		Counter      *int   `json:"counter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CredentialID == "" || body.Counter == nil || *body.Counter < 0 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}

	user, err := db.GetUserByID(reqUser.Sub)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "User not found"})
			return
		}
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to verify authentication"})
		return
	}

	idx := -1
	for i, c := range user.WebAuthnCredentials {
		if c.ID == body.CredentialID {
			idx = i
			break
		}
	}
	if idx == -1 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Credential not found"})
		return
	}

	storedCounter := user.WebAuthnCredentials[idx].Counter
	newCounter := *body.Counter
	if storedCounter > 0 && newCounter <= storedCounter {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid counter (possible cloned authenticator)"})
		return
	}

	user.WebAuthnCredentials[idx].Counter = newCounter
	user.WebAuthnChallenge = ""
	if err := db.SaveUser(user); err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to verify authentication"})
		return
	}

	token, expiresAt, err := webauthn.GenerateDecryptionToken(user.ID, 300)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to verify authentication"})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": expiresAt,
	})
}
