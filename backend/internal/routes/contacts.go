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

func ContactsRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequireAuth)
	r.Get("/", handleListContacts)
	r.Post("/", handleUpsertContact)
	r.Delete("/{id}", handleDeleteContact)
	return r
}

func isValidPublicKey(key string) bool {
	trimmed := strings.TrimSpace(key)
	if strings.Contains(trimmed, "BEGIN PUBLIC KEY") && strings.Contains(trimmed, "END PUBLIC KEY") {
		return true
	}
	if len(trimmed) >= 50 {
		cleaned := strings.Join(strings.Fields(trimmed), "")
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return false
		}
		return base64.StdEncoding.EncodeToString(decoded) == cleaned
	}
	return false
}

func handleListContacts(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || user.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	contacts, err := db.ListContactsByOwner(user.Sub)
	if err != nil {
		log.Printf("Failed to list contacts: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to list contacts"})
		return
	}

	// Update dynamic public keys for internal users
	for i := range contacts {
		acc, err := db.GetAccountByUsername(contacts[i].ContactUsername)
		if err == nil && acc != nil && acc.PublicKey != "" {
			contacts[i].PublicKey = acc.PublicKey
		}
	}

	if contacts == nil {
		contacts = []models.Contact{}
	}
	middleware.WriteJSON(w, http.StatusOK, contacts)
}

func handleUpsertContact(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || user.Sub == "" || user.Username == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	var body struct {
		ContactUsername string `json:"contactUsername"`
		PublicKey       string `json:"publicKey"`
		Label           string `json:"label"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}

	if len(body.ContactUsername) < 3 || len(body.ContactUsername) > 64 || len(body.Label) > 120 || len(body.Notes) > 500 {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid payload"})
		return
	}
	if body.PublicKey != "" && !isValidPublicKey(body.PublicKey) {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "Public key must be valid Base64 or PEM format"})
		return
	}

	if body.ContactUsername == user.Username {
		middleware.WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "자기 자신은 연락처로 추가할 수 없습니다."})
		return
	}

	finalPublicKey := strings.TrimSpace(body.PublicKey)
	if finalPublicKey == "" {
		acc, err := db.GetAccountByUsername(body.ContactUsername)
		if err != nil || acc == nil || acc.PublicKey == "" {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "사용자를 찾을 수 없거나 등록된 공개키가 없습니다."})
			return
		}
		finalPublicKey = acc.PublicKey
	}

	saved, created, err := db.UpsertContact(user.Sub, user.Username, body.ContactUsername, finalPublicKey, body.Label, body.Notes)
	if err != nil {
		log.Printf("Failed to store contact: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to store contact"})
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	middleware.WriteJSON(w, status, saved)
}

func handleDeleteContact(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || user.Sub == "" {
		middleware.WriteJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		return
	}

	id := chi.URLParam(r, "id")
	if err := db.DeleteContact(id, user.Sub); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			middleware.WriteJSON(w, http.StatusNotFound, map[string]string{"message": "Contact not found"})
			return
		}
		log.Printf("Failed to delete contact: %v", err)
		middleware.WriteJSON(w, http.StatusInternalServerError, map[string]string{"message": "Failed to delete contact"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
