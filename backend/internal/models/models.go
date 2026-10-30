package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type WebAuthnCredential struct {
	ID         string   `json:"id"`
	PublicKey  string   `json:"publicKey"`
	Counter    int      `json:"counter"`
	Transports []string `json:"transports,omitempty"`
}

type User struct {
	ID                  string               `json:"id"`
	Username            string               `json:"username"`
	PasswordHash        string               `json:"-"`
	WebAuthnCredentials []WebAuthnCredential `json:"webauthnCredentials,omitempty"`
	WebAuthnChallenge   string               `json:"-"`
	CreatedAt           time.Time            `json:"createdAt"`
	UpdatedAt           time.Time            `json:"updatedAt"`
}

type EncryptedPrivateKey struct {
	CipherText string `json:"cipherText"`
	IV         string `json:"iv"`
	AuthTag    string `json:"authTag,omitempty"`
}

type KdfParameters struct {
	Algorithm   string `json:"algorithm"`
	Salt        string `json:"salt"`
	Iterations  *int   `json:"iterations,omitempty"`
	MemoryCost  *int   `json:"memoryCost,omitempty"`
	Parallelism *int   `json:"parallelism,omitempty"`
	KeyLength   *int   `json:"keyLength,omitempty"`
	Hash        string `json:"hash,omitempty"`
}

type AccountPayload struct {
	Username            string              `json:"username"`
	PublicKey           string              `json:"publicKey"`
	EncryptedPrivateKey EncryptedPrivateKey `json:"encryptedPrivateKey"`
	Kdf                 KdfParameters       `json:"kdf"`
	Notes               string              `json:"notes,omitempty"`
}

type Account struct {
	ID                  string              `json:"id"`
	Username            string              `json:"username"`
	PublicKey           string              `json:"publicKey"`
	EncryptedPrivateKey EncryptedPrivateKey `json:"encryptedPrivateKey"`
	Kdf                 KdfParameters       `json:"kdf"`
	Notes               string              `json:"notes,omitempty"`
	CreatedAt           time.Time           `json:"createdAt"`
	UpdatedAt           time.Time           `json:"updatedAt"`
}

type Contact struct {
	ID              string    `json:"id"`
	OwnerID         string    `json:"-"`
	OwnerUsername   string    `json:"-"`
	ContactUsername string    `json:"contactUsername"`
	PublicKey       string    `json:"publicKey"`
	Label           string    `json:"label,omitempty"`
	Notes           string    `json:"notes,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}
