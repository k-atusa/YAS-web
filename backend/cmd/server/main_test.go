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

	"golang.org/x/crypto/argon2"
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
		Token  string `json:"token"`
		R0Salt string `json:"r0Salt"`
		User   struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&loginRes)
	resp.Body.Close()
	if loginRes.Token == "" {
		t.Fatal("expected JWT token")
	}
	r0SaltBytes, err := base64.StdEncoding.DecodeString(loginRes.R0Salt)
	if err != nil || len(r0SaltBytes) != 32 {
		t.Fatalf("expected 32-byte random r0Salt on login, got len=%d, err=%v", len(r0SaltBytes), err)
	}

	// 4. Verify weak PBKDF2 KDF is rejected (400 Bad Request)
	salt := []byte("0123456789abcdef")
	iv := []byte("0123456789ab") // 12 bytes
	weakPayload, _ := json.Marshal(map[string]any{
		"username":  "alice",
		"publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----",
		"encryptedPrivateKey": map[string]string{
			"cipherText": base64.StdEncoding.EncodeToString([]byte("ciphertext")),
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
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/accounts", bytes.NewReader(weakPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak PBKDF2 should be rejected with 400, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4.1 Upload Alice's Account (Encrypted Private Key with arg2st-prf / arg2st)
	prfSecret := []byte("0123456789abcdef0123456789abcdef")
	aesKey := argon2.IDKey(prfSecret, salt, 3, 65536, 4, 32)
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
			"algorithm":   "arg2st-prf",
			"salt":        base64.StdEncoding.EncodeToString(salt),
			"iterations":  3,
			"memoryCost":  262144,
			"parallelism": 6,
			"keyLength":   32,
			"hash":        "SHA3-512",
		},
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/accounts", bytes.NewReader(accPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("save account failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 5. Zero-Knowledge: Verify that server has NO decrypt endpoint (must return 404)
	decBody, _ := json.Marshal(map[string]string{"username": "alice"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/accounts/decrypt", bytes.NewReader(decBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("server must not expose a decrypt endpoint (Zero-Knowledge), got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5.1 Verify public lookup GET /api/accounts/username/alice does NOT leak encryptedPrivateKey or kdf
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/accounts/username/alice", nil)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get account failed: %v, status=%d", err, resp.StatusCode)
	}
	var rawPublicAcc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rawPublicAcc)
	resp.Body.Close()
	if _, leaked := rawPublicAcc["encryptedPrivateKey"]; leaked {
		t.Fatalf("public endpoint must NOT expose encryptedPrivateKey")
	}
	if _, leaked := rawPublicAcc["kdf"]; leaked {
		t.Fatalf("public endpoint must NOT expose kdf")
	}
	if rawPublicAcc["hasPrivateKey"] != true {
		t.Fatalf("expected hasPrivateKey=true on public account metadata")
	}

	// 5.2 Verify GET /api/accounts/me/vault without JWT is rejected with 401, and with ID/Password JWT succeeds
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/accounts/me/vault", nil)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated vault access must return 401, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/accounts/me/vault", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated vault access with ID/Password JWT must return 200, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. WebAuthn Multi-Device Register + Authenticate + Passkey Management
	// 6.1 Generate mock WebAuthn P-256 Authenticator Key for Passkey 1
	authenticatorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	pubKeyDer, err := x509.MarshalPKIXPublicKey(&authenticatorKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal pkix: %v", err)
	}
	credID := base64.StdEncoding.EncodeToString([]byte("alice/passkey+cred-1"))
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

	// 6.3 Register Verify Passkey 1 with wrapped Master Key (난수값0 + 결정적난수값1 -> 마스터키 암호화)
	regClientDataJSON := fmt.Sprintf(`{"type":"webauthn.create","challenge":"%s","origin":"http://localhost:4000"}`, regOptions.Options.Challenge)
	regVerifyBody, _ := json.Marshal(map[string]any{
		"credentialId":   credID,
		"publicKey":      pubKeyB64,
		"clientDataJSON": base64.StdEncoding.EncodeToString([]byte(regClientDataJSON)),
		"counter":        1,
		"transports":     []string{"internal"},
		"name":           "MacBook Touch ID",
		"encryptedMasterKey": map[string]string{
			"cipherText": base64.StdEncoding.EncodeToString([]byte("wrapped-master-key-1")),
			"iv":         base64.StdEncoding.EncodeToString(iv),
			"salt":       base64.StdEncoding.EncodeToString(salt),
		},
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-verify", bytes.NewReader(regVerifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-verify failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 6.3b Register Passkey 2 (Multi-device support: 패스키2 -> 난수값0 + 결정적난수값2 -> 마스터키 암호화)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-options", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-options 2 failed: %v, status=%d", err, resp.StatusCode)
	}
	_ = json.NewDecoder(resp.Body).Decode(&regOptions)
	resp.Body.Close()

	credID2 := base64.StdEncoding.EncodeToString([]byte("alice/passkey+cred-2"))
	regClientDataJSON2 := fmt.Sprintf(`{"type":"webauthn.create","challenge":"%s","origin":"http://localhost:4000"}`, regOptions.Options.Challenge)
	regVerifyBody2, _ := json.Marshal(map[string]any{
		"credentialId":   credID2,
		"publicKey":      pubKeyB64,
		"clientDataJSON": base64.StdEncoding.EncodeToString([]byte(regClientDataJSON2)),
		"counter":        1,
		"transports":     []string{"hybrid"},
		"name":           "iPhone Passkey",
		"encryptedMasterKey": map[string]string{
			"cipherText": base64.StdEncoding.EncodeToString([]byte("wrapped-master-key-2")),
			"iv":         base64.StdEncoding.EncodeToString(iv),
			"salt":       base64.StdEncoding.EncodeToString(salt),
		},
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/register-verify", bytes.NewReader(regVerifyBody2))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("webauthn register-verify 2 failed: %v, status=%d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 6.3c List passkeys (must NOT leak encryptedMasterKey without WebAuthn signature verification) and delete Passkey 2
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/webauthn/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("list webauthn credentials failed: %v, status=%d", err, resp.StatusCode)
	}
	var credList struct {
		Credentials []map[string]any `json:"credentials"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&credList)
	resp.Body.Close()
	if len(credList.Credentials) != 2 || credList.Credentials[0]["hasMasterKey"] != true || credList.Credentials[1]["hasMasterKey"] != true {
		t.Fatalf("expected 2 credentials with wrapped master keys, got %+v", credList.Credentials)
	}
	if _, leaked := credList.Credentials[0]["encryptedMasterKey"]; leaked {
		t.Fatalf("GET /api/webauthn/credentials must NOT leak encryptedMasterKey before WebAuthn signature verification")
	}

	delCredBody, _ := json.Marshal(map[string]string{"credentialId": credID2})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/webauthn/credentials/delete", bytes.NewReader(delCredBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("delete webauthn credential failed: %v, status=%d", err, resp.StatusCode)
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

	// 6.7 Verify valid cryptographic signature succeeds and returns encryptedMasterKey!
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
		Token              string `json:"token"`
		ExpiresAt          string `json:"expiresAt"`
		Verified           bool   `json:"verified"`
		EncryptedMasterKey *struct {
			CipherText string `json:"cipherText"`
		} `json:"encryptedMasterKey"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&authVerifyRes)
	resp.Body.Close()
	if !authVerifyRes.Verified || authVerifyRes.Token == "" || authVerifyRes.EncryptedMasterKey == nil {
		t.Fatalf("expected successful verification and encryptedMasterKey from webauthn authenticate-verify")
	}

	// 6.8 Use the one-time verificationToken to fetch the encrypted private key vault and decrypt locally
	vaultReqBody, _ := json.Marshal(map[string]string{
		"verificationToken": authVerifyRes.Token,
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/accounts/me/vault", bytes.NewReader(vaultReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/accounts/me/vault with valid verificationToken, got status=%d", resp.StatusCode)
	}
	var fetchedVault struct {
		Username            string `json:"username"`
		PublicKey           string `json:"publicKey"`
		EncryptedPrivateKey struct {
			CipherText string `json:"cipherText"`
			IV         string `json:"iv"`
		} `json:"encryptedPrivateKey"`
		KDF struct {
			Algorithm string `json:"algorithm"`
			Salt      string `json:"salt"`
			KeyLength int    `json:"keyLength"`
		} `json:"kdf"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&fetchedVault)
	resp.Body.Close()

	fetchedSalt, _ := base64.StdEncoding.DecodeString(fetchedVault.KDF.Salt)
	fetchedIV, _ := base64.StdEncoding.DecodeString(fetchedVault.EncryptedPrivateKey.IV)
	fetchedCipher, _ := base64.StdEncoding.DecodeString(fetchedVault.EncryptedPrivateKey.CipherText)
	clientDerivedKey := argon2.IDKey(prfSecret, fetchedSalt, 3, 65536, 4, uint32(fetchedVault.KDF.KeyLength))
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

	// 6.9 Verify that replaying the consumed verificationToken is rejected with 401
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/accounts/me/vault", bytes.NewReader(vaultReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed verificationToken must be rejected with 401, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 7. Account Deletion (계정 탈퇴)
	badDelBody, _ := json.Marshal(map[string]string{"password": "WrongPassword!"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/auth/delete-account", bytes.NewReader(badDelBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete-account with wrong password must return 401, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	goodDelBody, _ := json.Marshal(map[string]string{"password": "StrongPassword1!"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/auth/delete-account", bytes.NewReader(goodDelBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginRes.Token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("delete-account with valid password must return 200, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify Alice's account & keys are completely removed
	resp, err = client.Get(ts.URL + "/api/accounts/username/alice")
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted user's public key should return 404, got status=%d", resp.StatusCode)
	}
	resp.Body.Close()
}
