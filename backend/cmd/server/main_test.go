package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/db"

	"golang.org/x/crypto/pbkdf2"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	tmpDir := t.TempDir()

	config.App = config.Config{
		Port:      4000,
		DBPath:    filepath.Join(tmpDir, "test.db"),
		JWTSecret: "test-secret-key",
		Domain:    "localhost",
	}

	if err := db.Connect(config.App.DBPath); err != nil {
		t.Fatalf("failed to connect db: %v", err)
	}

	r, err := newRouter()
	if err != nil {
		t.Fatalf("failed to build router: %v", err)
	}

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

	// 4. Upload Alice's Account (Encrypted Private Key) - Zero-Knowledge Client-side encryption
	clientPassphrase := "Alice-Secure-Master-Password-123!"
	salt := []byte("0123456789abcdef")
	iv := []byte("0123456789ab") // 12 bytes
	aesKey := pbkdf2.Key([]byte(clientPassphrase), salt, 1000, 32, sha256.New)
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

	// 5. Zero-Knowledge: Verify that server has NO decrypt endpoint (must return 404/405)
	decBody, _ := json.Marshal(map[string]string{"username": "alice"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/accounts/decrypt", bytes.NewReader(decBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("server must not expose a decrypt endpoint (Zero-Knowledge), got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5.1 Verify client can fetch the stored encrypted vault and decrypt locally
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/accounts/username/alice", nil)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get account failed: %v, status=%d", err, resp.StatusCode)
	}
	var fetchedAcc struct {
		Username            string `json:"username"`
		PublicKey           string `json:"publicKey"`
		EncryptedPrivateKey struct {
			CipherText string `json:"cipherText"`
			IV         string `json:"iv"`
		} `json:"encryptedPrivateKey"`
		KDF struct {
			Salt       string `json:"salt"`
			Iterations int    `json:"iterations"`
			KeyLength  int    `json:"keyLength"`
		} `json:"kdf"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&fetchedAcc)
	resp.Body.Close()

	// Local client decryption
	fetchedSalt, _ := base64.StdEncoding.DecodeString(fetchedAcc.KDF.Salt)
	fetchedIV, _ := base64.StdEncoding.DecodeString(fetchedAcc.EncryptedPrivateKey.IV)
	fetchedCipher, _ := base64.StdEncoding.DecodeString(fetchedAcc.EncryptedPrivateKey.CipherText)
	clientDerivedKey := pbkdf2.Key([]byte(clientPassphrase), fetchedSalt, fetchedAcc.KDF.Iterations, fetchedAcc.KDF.KeyLength, sha256.New)
	cBlock, err := aes.NewCipher(clientDerivedKey)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	cGcm, err := cipher.NewGCM(cBlock)
	if err != nil {
		t.Fatalf("failed to create gcm: %v", err)
	}
	clientDecrypted, err := cGcm.Open(nil, fetchedIV, fetchedCipher, nil)
	if err != nil {
		t.Fatalf("client-side decryption failed: %v", err)
	}
	if string(clientDecrypted) != plainPrivKey {
		t.Fatalf("client-side decrypted key mismatch: got %q, want %q", string(clientDecrypted), plainPrivKey)
	}

	// 6. WebAuthn Register + Authenticate (Real cryptographic signature verification)
	// 6.1 Generate mock WebAuthn P-256 Authenticator Key
	authenticatorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	pubKeyDer, err := x509.MarshalPKIXPublicKey(&authenticatorKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal pkix: %v", err)
	}
	credID := base64.RawURLEncoding.EncodeToString([]byte("alice-passkey-cred-1"))
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyDer)

	// 6.2 Get Registration Options
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-options", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-options failed: %v, status=%d", err, resp.StatusCode)
	}
	var regOptions struct {
		Options struct {
			Challenge string `json:"challenge"`
		} `json:"options"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&regOptions)
	resp.Body.Close()

	// 6.3 Register Verify
	regClientDataJSON := fmt.Sprintf(`{"type":"webauthn.create","challenge":"%s","origin":"http://localhost:4000"}`, regOptions.Options.Challenge)
	regVerifyBody, _ := json.Marshal(map[string]any{
		"credentialId":   credID,
		"publicKey":      pubKeyB64,
		"clientDataJSON": base64.StdEncoding.EncodeToString([]byte(regClientDataJSON)),
		"counter":        1,
		"transports":     []string{"internal"},
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-verify", bytes.NewReader(regVerifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-verify failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 6.4 Get Authentication Options
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/authenticate-options", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn authenticate-options failed: %v, status=%d", err, resp.StatusCode)
	}
	var authOptions struct {
		Options struct {
			Challenge string `json:"challenge"`
		} `json:"options"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&authOptions)
	resp.Body.Close()

	// 6.5 Prepare clientDataJSON, authenticatorData, and sign
	authClientDataJSON := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"http://localhost:4000"}`, authOptions.Options.Challenge)
	authClientDataBytes := []byte(authClientDataJSON)

	rpIdHash := sha256.Sum256([]byte("localhost"))
	authData := make([]byte, 37)
	copy(authData[0:32], rpIdHash[:])
	authData[32] = 0x01                            // UP: User Present flag
	binary.BigEndian.PutUint32(authData[33:37], 2) // counter = 2

	// 6.6 Verify invalid signature is rejected with 400
	badVerifyBody, _ := json.Marshal(map[string]any{
		"credentialId":      credID,
		"clientDataJSON":    base64.StdEncoding.EncodeToString(authClientDataBytes),
		"authenticatorData": base64.StdEncoding.EncodeToString(authData),
		"signature":         base64.StdEncoding.EncodeToString([]byte("invalid-fake-signature")),
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/authenticate-verify", bytes.NewReader(badVerifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("fake signature should be rejected with 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Re-fetch authenticate options because challenge was consumed/attempted
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/authenticate-options", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("re-fetch authenticate options failed: %v, status=%d", err, resp.StatusCode)
	}
	_ = json.NewDecoder(resp.Body).Decode(&authOptions)
	resp.Body.Close()

	// Re-sign with new challenge
	authClientDataJSON = fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"http://localhost:4000"}`, authOptions.Options.Challenge)
	authClientDataBytes = []byte(authClientDataJSON)
	cdataHash := sha256.Sum256(authClientDataBytes)
	signedData := append(authData, cdataHash[:]...)
	digest := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, authenticatorKey, digest[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// 6.7 Verify valid cryptographic signature succeeds!
	goodVerifyBody, _ := json.Marshal(map[string]any{
		"credentialId":      credID,
		"clientDataJSON":    base64.StdEncoding.EncodeToString(authClientDataBytes),
		"authenticatorData": base64.StdEncoding.EncodeToString(authData),
		"signature":         base64.StdEncoding.EncodeToString(signature),
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/authenticate-verify", bytes.NewReader(goodVerifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn authenticate-verify failed: %v, status=%d", err, resp.StatusCode)
	}
	var authVerifyRes struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
		Verified  bool   `json:"verified"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&authVerifyRes)
	resp.Body.Close()
	if !authVerifyRes.Verified || authVerifyRes.Token == "" {
		t.Fatalf("expected successful verification from webauthn authenticate-verify")
	}
}
