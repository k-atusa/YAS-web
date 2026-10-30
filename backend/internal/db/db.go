package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"yas-web-backend/internal/models"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

var ErrNotFound = errors.New("record not found")
var ErrConflict = errors.New("record already exists")

func Connect(dbPath string) error {
	if dbPath == "" {
		return errors.New("missing database path")
	}

	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			log.Printf("Warning: failed to execute %s: %v", p, err)
		}
	}

	if err := migrate(conn); err != nil {
		return fmt.Errorf("failed to migrate database schema: %w", err)
	}

	DB = conn
	log.Printf("Connected to SQLite (%s)", dbPath)
	return nil
}

func migrate(conn *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		webauthn_credentials TEXT NOT NULL DEFAULT '[]',
		webauthn_challenge TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

	CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		encrypted_private_key TEXT NOT NULL,
		kdf TEXT NOT NULL,
		notes TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_keys_username ON keys(username);

	CREATE TABLE IF NOT EXISTS contacts (
		id TEXT PRIMARY KEY,
		owner_id TEXT NOT NULL,
		owner_username TEXT NOT NULL,
		contact_username TEXT NOT NULL,
		public_key TEXT NOT NULL,
		label TEXT NOT NULL DEFAULT '',
		notes TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		UNIQUE(owner_id, contact_username)
	);
	CREATE INDEX IF NOT EXISTS idx_contacts_owner_id ON contacts(owner_id);
	`
	_, err := conn.Exec(schema)
	return err
}

// ==================== User Operations ====================

func CreateUser(username, passwordHash string) (*models.User, error) {
	existing, err := GetUserByUsername(username)
	if err == nil && existing != nil {
		return nil, ErrConflict
	}

	now := time.Now().UTC()
	user := &models.User{
		ID:                  models.NewID(),
		Username:            username,
		PasswordHash:        passwordHash,
		WebAuthnCredentials: []models.WebAuthnCredential{},
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	credsJSON, _ := json.Marshal(user.WebAuthnCredentials)
	_, err = DB.Exec(
		`INSERT INTO users (id, username, password_hash, webauthn_credentials, webauthn_challenge, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.PasswordHash, string(credsJSON), "", user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func GetUserByUsername(username string) (*models.User, error) {
	row := DB.QueryRow(
		`SELECT id, username, password_hash, webauthn_credentials, webauthn_challenge, created_at, updated_at
		 FROM users WHERE username = ?`,
		username,
	)
	return scanUser(row)
}

func GetUserByID(id string) (*models.User, error) {
	row := DB.QueryRow(
		`SELECT id, username, password_hash, webauthn_credentials, webauthn_challenge, created_at, updated_at
		 FROM users WHERE id = ?`,
		id,
	)
	return scanUser(row)
}

func SaveUser(user *models.User) error {
	user.UpdatedAt = time.Now().UTC()
	if user.WebAuthnCredentials == nil {
		user.WebAuthnCredentials = []models.WebAuthnCredential{}
	}
	credsJSON, err := json.Marshal(user.WebAuthnCredentials)
	if err != nil {
		return err
	}
	_, err = DB.Exec(
		`UPDATE users SET username = ?, password_hash = ?, webauthn_credentials = ?, webauthn_challenge = ?, updated_at = ?
		 WHERE id = ?`,
		user.Username, user.PasswordHash, string(credsJSON), user.WebAuthnChallenge, user.UpdatedAt, user.ID,
	)
	return err
}

func scanUser(row *sql.Row) (*models.User, error) {
	var u models.User
	var credsRaw string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &credsRaw, &u.WebAuthnChallenge, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if credsRaw != "" {
		_ = json.Unmarshal([]byte(credsRaw), &u.WebAuthnCredentials)
	}
	if u.WebAuthnCredentials == nil {
		u.WebAuthnCredentials = []models.WebAuthnCredential{}
	}
	return &u, nil
}

// ==================== Account (Keys) Operations ====================

func UpsertAccount(payload models.AccountPayload) (*models.Account, bool, error) {
	encKeyJSON, err := json.Marshal(payload.EncryptedPrivateKey)
	if err != nil {
		return nil, false, err
	}
	kdfJSON, err := json.Marshal(payload.Kdf)
	if err != nil {
		return nil, false, err
	}

	existing, err := GetAccountByUsername(payload.Username)
	now := time.Now().UTC()

	if errors.Is(err, ErrNotFound) {
		acc := &models.Account{
			ID:                  models.NewID(),
			Username:            payload.Username,
			PublicKey:           payload.PublicKey,
			EncryptedPrivateKey: payload.EncryptedPrivateKey,
			Kdf:                 payload.Kdf,
			Notes:               payload.Notes,
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		_, err = DB.Exec(
			`INSERT INTO keys (id, username, public_key, encrypted_private_key, kdf, notes, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			acc.ID, acc.Username, acc.PublicKey, string(encKeyJSON), string(kdfJSON), acc.Notes, acc.CreatedAt, acc.UpdatedAt,
		)
		if err != nil {
			return nil, false, err
		}
		return acc, true, nil
	} else if err != nil {
		return nil, false, err
	}

	if !now.After(existing.CreatedAt) {
		now = existing.CreatedAt.Add(time.Millisecond)
	}

	existing.PublicKey = payload.PublicKey
	existing.EncryptedPrivateKey = payload.EncryptedPrivateKey
	existing.Kdf = payload.Kdf
	existing.Notes = payload.Notes
	existing.UpdatedAt = now

	_, err = DB.Exec(
		`UPDATE keys SET public_key = ?, encrypted_private_key = ?, kdf = ?, notes = ?, updated_at = ?
		 WHERE username = ?`,
		existing.PublicKey, string(encKeyJSON), string(kdfJSON), existing.Notes, existing.UpdatedAt, existing.Username,
	)
	if err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

func GetAccountByUsername(username string) (*models.Account, error) {
	row := DB.QueryRow(
		`SELECT id, username, public_key, encrypted_private_key, kdf, notes, created_at, updated_at
		 FROM keys WHERE username = ?`,
		username,
	)
	return scanAccount(row)
}

func GetAccountByID(id string) (*models.Account, error) {
	row := DB.QueryRow(
		`SELECT id, username, public_key, encrypted_private_key, kdf, notes, created_at, updated_at
		 FROM keys WHERE id = ?`,
		id,
	)
	return scanAccount(row)
}

func scanAccount(row *sql.Row) (*models.Account, error) {
	var a models.Account
	var encKeyRaw, kdfRaw string
	err := row.Scan(&a.ID, &a.Username, &a.PublicKey, &encKeyRaw, &kdfRaw, &a.Notes, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(encKeyRaw), &a.EncryptedPrivateKey)
	_ = json.Unmarshal([]byte(kdfRaw), &a.Kdf)
	return &a, nil
}

// ==================== Contact Operations ====================

func ListContactsByOwner(ownerID string) ([]models.Contact, error) {
	rows, err := DB.Query(
		`SELECT id, owner_id, owner_username, contact_username, public_key, label, notes, created_at, updated_at
		 FROM contacts WHERE owner_id = ? ORDER BY created_at DESC`,
		ownerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	contacts := []models.Contact{}
	for rows.Next() {
		var c models.Contact
		if err := rows.Scan(&c.ID, &c.OwnerID, &c.OwnerUsername, &c.ContactUsername, &c.PublicKey, &c.Label, &c.Notes, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

func GetContactByID(id string) (*models.Contact, error) {
	var c models.Contact
	err := DB.QueryRow(
		`SELECT id, owner_id, owner_username, contact_username, public_key, label, notes, created_at, updated_at
		 FROM contacts WHERE id = ?`,
		id,
	).Scan(&c.ID, &c.OwnerID, &c.OwnerUsername, &c.ContactUsername, &c.PublicKey, &c.Label, &c.Notes, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func UpsertContact(ownerID, ownerUsername, contactUsername, publicKey, label, notes string) (*models.Contact, bool, error) {
	var existing models.Contact
	err := DB.QueryRow(
		`SELECT id, owner_id, owner_username, contact_username, public_key, label, notes, created_at, updated_at
		 FROM contacts WHERE owner_id = ? AND contact_username = ?`,
		ownerID, contactUsername,
	).Scan(&existing.ID, &existing.OwnerID, &existing.OwnerUsername, &existing.ContactUsername, &existing.PublicKey, &existing.Label, &existing.Notes, &existing.CreatedAt, &existing.UpdatedAt)

	now := time.Now().UTC()
	if errors.Is(err, sql.ErrNoRows) {
		c := &models.Contact{
			ID:              models.NewID(),
			OwnerID:         ownerID,
			OwnerUsername:   ownerUsername,
			ContactUsername: contactUsername,
			PublicKey:       publicKey,
			Label:           label,
			Notes:           notes,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_, err = DB.Exec(
			`INSERT INTO contacts (id, owner_id, owner_username, contact_username, public_key, label, notes, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, c.OwnerID, c.OwnerUsername, c.ContactUsername, c.PublicKey, c.Label, c.Notes, c.CreatedAt, c.UpdatedAt,
		)
		if err != nil {
			return nil, false, err
		}
		return c, true, nil
	} else if err != nil {
		return nil, false, err
	}

	if !now.After(existing.CreatedAt) {
		now = existing.CreatedAt.Add(time.Millisecond)
	}
	existing.OwnerUsername = ownerUsername
	existing.PublicKey = publicKey
	existing.Label = label
	existing.Notes = notes
	existing.UpdatedAt = now

	_, err = DB.Exec(
		`UPDATE contacts SET owner_username = ?, public_key = ?, label = ?, notes = ?, updated_at = ?
		 WHERE id = ?`,
		existing.OwnerUsername, existing.PublicKey, existing.Label, existing.Notes, existing.UpdatedAt, existing.ID,
	)
	if err != nil {
		return nil, false, err
	}
	return &existing, false, nil
}

func DeleteContact(id, ownerID string) error {
	res, err := DB.Exec(`DELETE FROM contacts WHERE id = ? AND owner_id = ?`, id, ownerID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
