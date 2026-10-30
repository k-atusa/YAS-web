package routes

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"yas-web-backend/internal/config"
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
		CredentialID   string   `json:"credentialId"`
		PublicKey      string   `json:"publicKey"`
		ClientDataJSON string   `json:"clientDataJSON"`
		Counter        *int     `json:"counter"`
		Transports     []string `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}
	if body.CredentialID == "" || body.PublicKey == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "credentialId and publicKey are required"})
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

	// 1. Verify challenge from clientDataJSON if provided
	if user.WebAuthnChallenge != "" && body.ClientDataJSON != "" {
		cdataBytes, err := webauthn.DecodeBase64Flexible(body.ClientDataJSON)
		if err != nil {
			middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid clientDataJSON base64"})
			return
		}
		if err := webauthn.VerifyClientData(cdataBytes, "webauthn.create", user.WebAuthnChallenge); err != nil {
			log.Printf("[WebAuthn] Register ClientData verification failed: %v", err)
			middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Registration challenge failed: " + err.Error()})
			return
		}
	}

	// 2. Validate Public Key structure (must be valid SPKI ASN.1 DER)
	if err := webauthn.ValidatePublicKey(body.PublicKey); err != nil {
		log.Printf("[WebAuthn] Invalid public key: %v", err)
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid public key: " + err.Error()})
		return
	}

	// Check if credential already registered
	for _, c := range user.WebAuthnCredentials {
		if c.ID == body.CredentialID {
			middleware.WriteJSON(w, http.StatusConflict, map[string]string{"message": "Credential already registered"})
			return
		}
	}

	initialCounter := 0
	if body.Counter != nil && *body.Counter >= 0 {
		initialCounter = *body.Counter
	}

	user.WebAuthnCredentials = append(user.WebAuthnCredentials, models.WebAuthnCredential{
		ID:         body.CredentialID,
		PublicKey:  body.PublicKey,
		Counter:    initialCounter,
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
		CredentialID      string `json:"credentialId"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}
	if body.CredentialID == "" || body.ClientDataJSON == "" || body.AuthenticatorData == "" || body.Signature == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "credentialId, clientDataJSON, authenticatorData, and signature are required"})
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

	if user.WebAuthnChallenge == "" {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "No active authentication challenge found"})
		return
	}

	// 1. Find matching credential
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

	// 2. Decode clientDataJSON and verify challenge & type
	cdataBytes, err := webauthn.DecodeBase64Flexible(body.ClientDataJSON)
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid clientDataJSON base64"})
		return
	}
	if err := webauthn.VerifyClientData(cdataBytes, "webauthn.get", user.WebAuthnChallenge); err != nil {
		log.Printf("[WebAuthn] ClientData verification failed: %v", err)
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "ClientData verification failed: " + err.Error()})
		return
	}

	// 3. Decode authenticatorData and verify RP ID hash, flags, counter
	authDataBytes, err := webauthn.DecodeBase64Flexible(body.AuthenticatorData)
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid authenticatorData base64"})
		return
	}
	newCounter, err := webauthn.VerifyAuthenticatorData(authDataBytes, config.App.Domain, user.WebAuthnCredentials[idx].Counter)
	if err != nil {
		log.Printf("[WebAuthn] AuthenticatorData verification failed: %v", err)
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "AuthenticatorData verification failed: " + err.Error()})
		return
	}

	// 4. Decode signature and verify cryptographic signature
	sigBytes, err := webauthn.DecodeBase64Flexible(body.Signature)
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid signature base64"})
		return
	}
	if err := webauthn.VerifySignature(user.WebAuthnCredentials[idx].PublicKey, authDataBytes, cdataBytes, sigBytes); err != nil {
		log.Printf("[WebAuthn] Signature verification failed: %v", err)
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Signature verification failed: invalid passkey signature"})
		return
	}

	// 5. Update user state (counter & consume challenge to prevent replay)
	user.WebAuthnCredentials[idx].Counter = newCounter
	user.WebAuthnChallenge = ""
	if err := db.SaveUser(user); err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to verify authentication"})
		return
	}

	// 6. Issue 5-minute decryption token
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
