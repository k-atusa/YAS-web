package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/db"
	"yas-web-backend/internal/middleware"
	"yas-web-backend/internal/routes"
	"yas-web-backend/internal/webui"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/pbkdf2"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	tmpDir := t.TempDir()

	config.App = config.Config{
		Port:         4000,
		DBPath:       filepath.Join(tmpDir, "test.db"),
		CorsOrigin:   "*",
		JWTSecret:    "test-secret-key",
		WebAuthnRPID: "localhost",
	}

	if err := db.Connect(config.App.DBPath); err != nil {
		t.Fatalf("failed to connect db: %v", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.CORS)

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		middleware.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Mount("/api/auth", routes.AuthRouter())
	r.Mount("/api/accounts", routes.AccountsRouter())
	r.Mount("/api/contacts", routes.ContactsRouter())
	r.Mount("/api/webauthn", routes.WebAuthnRouter())

	embeddedFS, err := webui.FS()
	if err != nil {
		t.Fatalf("failed to load embedded frontend: %v", err)
	}
	embeddedFileServer := http.FileServer(http.FS(embeddedFS))

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		cleanPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanPath != "" {
			if f, err := embeddedFS.Open(cleanPath); err == nil {
				_ = f.Close()
				embeddedFileServer.ServeHTTP(w, r)
				return
			}
		}
		serveEmbeddedIndexHTML(w, r, embeddedFS)
	})

	return httptest.NewServer(r)
}

func TestEndToEndFlow(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	client := ts.Client()

	// 1. Health check & Embedded Frontend HTML check
	resp, err := client.Get(ts.URL + "/api/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health check failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = client.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("embedded frontend root failed: %v, status=%d", err, resp.StatusCode)
	}
	var htmlBuf bytes.Buffer
	_, _ = htmlBuf.ReadFrom(resp.Body)
	resp.Body.Close()
	if !strings.Contains(htmlBuf.String(), "<div id=\"root\"></div>") {
		t.Fatalf("expected embedded index.html, got: %s", htmlBuf.String())
	}

	// 2. Signup Alice & Bob
	for _, u := range []string{"alice", "bob"} {
		body, _ := json.Marshal(map[string]string{
			"username": u,
			"password": "StrongPassword1!",
		})
		resp, err := client.Post(ts.URL+"/api/auth/signup", "application/json", bytes.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("signup %s failed: %v, status=%d", u, err, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// 3. Login Alice
	loginBody, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "StrongPassword1!",
	})
	resp, err = client.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %v, status=%d", err, resp.StatusCode)
	}
	var loginRes struct {
		Token string `json:"token"`
		User  struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&loginRes)
	resp.Body.Close()
	if loginRes.Token == "" {
		t.Fatal("expected JWT token")
	}

	// 4. Upload Alice's Account (Key) and test PBKDF2 + AES-GCM decrypt
	salt := []byte("0123456789abcdef")
	iv := []byte("0123456789ab") // 12 bytes
	aesKey := pbkdf2.Key([]byte("alice"), salt, 1000, 32, sha256.New)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	plainPrivKey := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----"
	sealed := gcm.Seal(nil, iv, []byte(plainPrivKey), nil)

	accPayload, _ := json.Marshal(map[string]any{
		"username":  "alice",
		"publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----",
		"encryptedPrivateKey": map[string]string{
			"cipherText": base64.StdEncoding.EncodeToString(sealed),
			"iv":         base64.StdEncoding.EncodeToString(iv),
		},
		"kdf": map[string]any{
			"algorithm":  "PBKDF2",
			"salt":       base64.StdEncoding.EncodeToString(salt),
			"iterations": 1000,
			"keyLength":  32,
			"hash":       "SHA-256",
		},
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/accounts", bytes.NewReader(accPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("save account failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 5. Decrypt Alice's Private Key
	decBody, _ := json.Marshal(map[string]string{"username": "alice"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/accounts/decrypt", bytes.NewReader(decBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("decrypt account failed: %v, status=%d", err, resp.StatusCode)
	}
	var decRes struct {
		PrivateKey string `json:"privateKey"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&decRes)
	resp.Body.Close()
	if decRes.PrivateKey != plainPrivKey {
		t.Fatalf("decrypted private key mismatch: got %q", decRes.PrivateKey)
	}

	// 6. WebAuthn Register + Authenticate
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-options", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-options failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	credID := base64.StdEncoding.EncodeToString([]byte("test-cred-id-1234"))
	pubKey := base64.StdEncoding.EncodeToString([]byte("test-pub-key-1234"))
	regVerifyBody, _ := json.Marshal(map[string]any{
		"credentialId": credID,
		"publicKey":    pubKey,
		"counter":      1,
		"transports":   []string{"internal"},
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-verify", bytes.NewReader(regVerifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-verify failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	authVerifyBody, _ := json.Marshal(map[string]any{
		"credentialId": credID,
		"counter":      2,
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/authenticate-verify", bytes.NewReader(authVerifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn authenticate-verify failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()
}
