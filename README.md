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

### 1. Pre-built Binary (Recommended)
No Go or Node.js runtime is required.

1. Download the binary matching your platform from the [GitHub Releases](https://github.com/k-atusa/YAS-web/releases) page.

2. Grant execution permission (Linux / macOS):
   ```bash
   chmod +x yas-web*
   ```

3. Run the binary (starts both backend API & embedded frontend on default `http://localhost:4000`):
   ```bash
   # Linux / macOS (wildcard matches any downloaded version)
   ./yas-web-*

   # Windows (PowerShell / Command Prompt)
   .\yas-web-*.exe
   ```

### 2. Manual Build from Source
Prerequisites: Go 1.26+ and Node.js 18+.

The compiled frontend (`index.html`, JS, CSS) is embedded directly into the Go binary via `embed.FS`.

```bash
# 1. Build frontend
cd frontend && npm install && npm run build && cd ..

# 2. Build Go single-binary with embedded frontend
cd backend && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../yas-web-$(go env GOOS)-$(go env GOARCH) ./cmd/server && cd ..

# 3. Run the compiled binary for your current OS & architecture
./yas-web-*
```

## Environment variables
All settings have safe defaults, so **no `.env` file is required** to run locally.

To customize settings (e.g. in production), create a `.env` file in the same directory as the binary (see `.env.example`):
- `PORT` – Server port (default: `4000`)
- `JWT_SECRET` – Secret key for JWT signing (optional; auto-generated random 32-byte secret in memory if omitted)
- `DOMAIN` – Domain name for WebAuthn passkeys (default: `localhost`, set to your domain like `example.com` in production)

*(SQLite database is automatically stored in `./data/yas-web.db`)*
