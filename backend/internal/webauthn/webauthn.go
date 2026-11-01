package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateChallenge() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func GenerateRegistrationOptions(username, userID, challenge string) map[string]any {
	return map[string]any{
		"challenge": challenge,
		"rp": map[string]any{
			"name": "YAS Web",
			"id":   config.App.Domain,
		},
		"user": map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString([]byte(userID)),
			"name":        username,
			"displayName": username,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"timeout":     60000,
		"attestation": "none",
		"authenticatorSelection": map[string]any{
			"authenticatorAttachment": "platform",
			"residentKey":             "preferred",
			"userVerification":        "preferred",
		},
	}
}

func GenerateAuthenticationOptions(challenge string, allowedCredentials []models.WebAuthnCredential) map[string]any {
	allowCreds := make([]map[string]any, 0, len(allowedCredentials))
	for _, cred := range allowedCredentials {
		allowCreds = append(allowCreds, map[string]any{
			"type":       "public-key",
			"id":         cred.ID,
			"transports": []string{"usb", "nfc", "ble", "internal"},
		})
	}

	return map[string]any{
		"challenge":        challenge,
		"timeout":          60000,
		"userVerification": "preferred",
		"allowCredentials": allowCreds,
	}
}

func DecodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

type CollectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func VerifyClientData(clientDataJSONBytes []byte, expectedType, storedChallenge string) error {
	var cdata CollectedClientData
	if err := json.Unmarshal(clientDataJSONBytes, &cdata); err != nil {
		return errors.New("malformed clientDataJSON")
	}
	if cdata.Type != expectedType {
		return fmt.Errorf("unexpected clientData type: got %q, expected %q", cdata.Type, expectedType)
	}

	clientChalBytes, err := DecodeBase64Flexible(cdata.Challenge)
	if err != nil {
		return errors.New("invalid challenge in clientDataJSON")
	}
	storedChalBytes, err := DecodeBase64Flexible(storedChallenge)
	if err != nil {
		return errors.New("invalid stored challenge")
	}
	if !bytes.Equal(clientChalBytes, storedChalBytes) {
		return errors.New("challenge mismatch")
	}

	if config.App.Domain != "" && config.App.Domain != "localhost" {
		if !strings.Contains(cdata.Origin, config.App.Domain) {
			return fmt.Errorf("origin mismatch: got %q, expected domain %q", cdata.Origin, config.App.Domain)
		}
	}
	return nil
}

func VerifyAuthenticatorData(authData []byte, expectedRPID string, storedCounter int) (int, error) {
	if len(authData) < 37 {
		return 0, errors.New("authenticatorData too short (must be at least 37 bytes)")
	}

	expectedHash := sha256.Sum256([]byte(expectedRPID))
	if !bytes.Equal(authData[0:32], expectedHash[:]) {
		// Allow fallback to localhost for local testing
		localHash := sha256.Sum256([]byte("localhost"))
		if !bytes.Equal(authData[0:32], localHash[:]) {
			return 0, errors.New("rpIdHash mismatch")
		}
	}

	flags := authData[32]
	if flags&0x01 == 0 {
		return 0, errors.New("user present (UP) flag not set")
	}

	newCounter := int(binary.BigEndian.Uint32(authData[33:37]))
	if storedCounter > 0 && newCounter <= storedCounter {
		return 0, errors.New("invalid counter: potential cloned authenticator")
	}

	return newCounter, nil
}

func ValidatePublicKey(pubKeyBase64 string) error {
	pubKeyBytes, err := DecodeBase64Flexible(pubKeyBase64)
	if err != nil {
		return errors.New("invalid public key base64")
	}
	pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid SPKI public key: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T (must be ECDSA or RSA)", pub)
	}
}

func VerifySignature(storedPubKeyBase64 string, authData, clientDataJSONBytes, sigBytes []byte) error {
	pubKeyBytes, err := DecodeBase64Flexible(storedPubKeyBase64)
	if err != nil {
		return errors.New("invalid stored public key base64")
	}

	pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse stored public key: %w", err)
	}

	cdataHash := sha256.Sum256(clientDataJSONBytes)
	signedData := make([]byte, 0, len(authData)+32)
	signedData = append(signedData, authData...)
	signedData = append(signedData, cdataHash[:]...)

	digest := sha256.Sum256(signedData)

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], sigBytes) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sigBytes); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// GenerateVerificationToken issues a signed token certifying successful WebAuthn authentication.
func GenerateVerificationToken(userID string, expirySeconds int) (string, time.Time, error) {
	if expirySeconds <= 0 {
		expirySeconds = 60
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(expirySeconds) * time.Second)

	claims := jwt.MapClaims{
		"sub":  userID,
		"type": "webauthn_verified",
		"iat":  now.Unix(),
		"exp":  expiresAt.Unix(),
		"jti":  GenerateChallenge(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(config.App.JWTSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}
