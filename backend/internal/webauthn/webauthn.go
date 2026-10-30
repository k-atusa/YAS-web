package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"yas-web-backend/internal/config"
	"yas-web-backend/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateChallenge() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func GenerateRegistrationOptions(username, userID, challenge string) map[string]any {
	return map[string]any{
		"challenge": challenge,
		"rp": map[string]any{
			"name": "YAS Web",
			"id":   config.App.Domain,
		},
		"user": map[string]any{
			"id":          base64.StdEncoding.EncodeToString([]byte(userID)),
			"name":        username,
			"displayName": username,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"timeout":     60000,
		"attestation": "direct",
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

func IsValidBase64(str string) bool {
	cleaned := strings.Join(strings.Fields(str), "")
	if cleaned == "" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return false
	}
	return base64.StdEncoding.EncodeToString(decoded) == cleaned
}

func GenerateDecryptionToken(userID string, expirySeconds int) (string, time.Time, error) {
	if expirySeconds <= 0 {
		expirySeconds = 300
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(expirySeconds) * time.Second)

	claims := jwt.MapClaims{
		"sub":  userID,
		"type": "decrypt",
		"iat":  now.Unix(),
		"exp":  expiresAt.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(config.App.JWTSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func VerifyDecryptionToken(tokenStr string) (string, error) {

	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(config.App.JWTSecret), nil
	})
	if err != nil || !tok.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}
	typ, _ := claims["type"].(string)
	if typ != "decrypt" {
		return "", errors.New("invalid token type")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("missing sub")
	}
	return sub, nil
}
