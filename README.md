# YAS-web

Encrypted-key storage & client-side encryption platform. Key pairs (PQC / Curve448) are generated in the browser, the private key is wrapped with a PBKDF2-derived AES-GCM key, and only ciphertext plus KDF metadata ever reach the server. A JWT-protected API lets you sync encrypted key material, manage contacts, and authenticate via WebAuthn passkeys.

## Architecture
- **Backend**: Go (`net/http` + `chi` router) + SQLite (`modernc.org/sqlite`).
  - `/api/auth` handles signup/login and issues JWTs.
  - `/api/accounts` stores, fetches, and decrypts encrypted key material (guarded by `Authorization: Bearer <token>`).
  - `/api/contacts` manages contact public keys.
  - `/api/webauthn` handles WebAuthn passkey registration, verification, and short-lived decryption tokens.
- **Frontend**: React + Vite + TypeScript.
- **Data shape**: `{ username, publicKey, encryptedPrivateKey: { cipherText, iv, authTag? }, kdf: { algorithm, salt, keyLength, iterations?, memoryCost?, parallelism?, hash? }, notes, timestamps }`.

## Quick start
Prereqs: Go 1.26+ (and Node 18+ if rebuilding the frontend).
*(Note: If you run the pre-built release binary directly, neither Go nor Node is required.)*

### Single-binary execution (Backend + Embedded Frontend)
The compiled frontend (`index.html`, JS, CSS) is embedded directly into the Go binary via `embed.FS`.
```bash
# Build frontend + embed into Go binary (v2.0.0)
cd frontend && npm install && npm run build && cd ..
cd backend && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../yas-web-2.0.0-$(go env GOOS)-$(go env GOARCH) ./cmd/server && cd ..

# Run both frontend & backend at once (default http://localhost:4000)
./yas-web-2.0.0-darwin-arm64
```

## Environment variables
- `backend/.env`
  - `DB_PATH` – SQLite database file path (default `./data/yas-web.db`)
  - `PORT` – API port (default `4000`, `.env.example` sets `7001`)
  - `JWT_SECRET` – signing key for auth tokens (required in prod)
  - `CORS_ORIGIN` – frontend origin allowed by CORS (default `*`)
  - `WEBAUTHN_RP_ID` – WebAuthn Relying Party ID (default `localhost`)
- `frontend/.env`
  - `VITE_API_BASE` – base URL for API requests (default `http://localhost:4000/api`)
