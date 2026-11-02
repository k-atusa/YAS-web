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

type WrappedMasterKey struct {
	CipherText string `json:"cipherText"`
	IV         string `json:"iv"`
	Salt       string `json:"salt"`
}

type WebAuthnCredential struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name,omitempty"`
	PublicKey          string            `json:"publicKey"`
	Counter            int               `json:"counter"`
	Transports         []string          `json:"transports,omitempty"`
	EncryptedMasterKey *WrappedMasterKey `json:"encryptedMasterKey,omitempty"`
	CreatedAt          time.Time         `json:"createdAt"`
}

type User struct {
	ID                  string               `json:"id"`
	Username            string               `json:"username"`
	PasswordHash        string               `json:"-"`
	R0Salt              string               `json:"r0Salt,omitempty"`
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

type PublicAccount struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	PublicKey     string    `json:"publicKey"`
	HasPrivateKey bool      `json:"hasPrivateKey"`
	Notes         string    `json:"notes,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type AccountVaultResponse struct {
	Username            string              `json:"username"`
	PublicKey           string              `json:"publicKey"`
	EncryptedPrivateKey EncryptedPrivateKey `json:"encryptedPrivateKey"`
	Kdf                 KdfParameters       `json:"kdf"`
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
