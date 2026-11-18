# YAS-web

Encrypted-key storage & client-side encryption platform. Key pairs (PQC) are generated in the browser, the private key is wrapped with an Argon2id (`arg2st`)-derived AES-256-GCM key, and only ciphertext plus KDF metadata ever reach the server. A JWT-protected API lets you sync encrypted key material, manage contacts, and authenticate via WebAuthn passkeys.

## Architecture
- **Backend**: Go (`net/http` + `chi` router) + SQLite (`modernc.org/sqlite`).
  - `/api/auth` handles signup/login, password verification, and JWT issuance.
  - `/api/accounts` stores and fetches encrypted key material (guarded by `Authorization: Bearer <token>`; decryption occurs strictly client-side).
  - `/api/contacts` manages contact public keys.
  - `/api/webauthn` handles WebAuthn passkey registration, verification, and short-lived verification tokens.
- **Frontend**: React + Vite + TypeScript.
- **Data shape**: `{ username, publicKey, encryptedPrivateKey: { cipherText, iv, authTag? }, kdf: { algorithm, salt, keyLength, iterations?, memoryCost?, parallelism?, hash? }, notes, timestamps }`.

## Key Model & Security Boundaries

YAS-web separates **account authentication** from **cryptographic key protection** so that compromising the server or your login credentials alone cannot expose your private key.

| Key / Secret | Purpose | Exposed to Server? | How It Is Protected & Used |
| --- | --- | --- | --- |
| **Normal Account Key (Account Password)** | Account login, session auth (JWT), account deletion, and `R0` derivation | **Yes** (sent during auth) | Sent to `/api/auth/*`, hashed server-side with `arg2st` (Argon2id + HMAC-SHA3-512), and stored as `password_hash`. Never decrypts the PQC private key directly. |
| **Master Key** | Encrypting/decrypting the PQC Private Key | **No** (client-only) | 5-word hyphen-delimited passphrase kept strictly in the browser. Derives an AES-256-GCM key via `arg2st` to wrap/unwrap the PQC private key locally. |
| **PQC Key Pair (Public / Private Key)** | End-to-end encryption & digital signatures (`pqc1`) | Public: **Yes**<br>Private: **Ciphertext only** | Public key is stored in plaintext for peer lookup. Private key is encrypted with the Master Key before upload and decrypted only in browser memory. |

### 1. Normal Account Key (Account Password) — Server-Exposed
- **Authentication & API access**: Your account password is transmitted to the backend during signup, login, password re-verification, and account deletion (`/api/auth/signup`, `/api/auth/login`, `/api/auth/verify-password`, `/api/auth/delete-account`).
- **Server-side storage**: The backend hashes it using `arg2st` (Argon2id: `m=262144` KiB, `t=3`, `p=6` + HMAC-SHA3-512) and stores `password_hash` alongside a per-user 32-byte `r0Salt`.
- **Vault access, not decryption**: A valid login grants a JWT to download your encrypted vault (`GET /api/accounts/me/vault`), **but the server and the account password alone cannot decrypt your PQC private key**.
- **Client-side `R0` derivation**: Upon login or password verification, the browser uses the server-returned `r0Salt` and your password to derive a 32-byte deterministic secret `R0 = arg2st(password, r0Salt)` in memory only (never sent back to the server). `R0` is used exclusively for passkey-based Master Key wrapping/unwrapping.

### 2. Master Key — Client-Only (Zero-Knowledge)
- **Never leaves the browser**: The Master Key is a 5-word hyphen-delimited passphrase generated client-side. It is **never transmitted to or stored on the server** in plaintext.
- **Root secret for your Private Key**: The browser derives an AES-256-GCM key from the Master Key via `arg2st` (`iterations=3`, `memoryCost=262144`, `parallelism=6`, `keyLength=32`, `hash="SHA3-512"`) to encrypt and decrypt your PQC private key locally. Only `{ cipherText, iv }` and `kdf` metadata are uploaded to the server, and the backend exposes no decryption endpoint.
- **Impact of compromise**: Even if the server database, TLS termination, or your account password + JWT are compromised, an attacker still cannot decrypt your stored PQC private key without the Master Key.
- **Multi-device WebAuthn Passkey binding (`R0 + Ri`)**: To unlock your private key without re-entering the Master Key each time, you can bind a WebAuthn passkey that supports the `prf` extension. Client-side, the browser combines `R0` (from your account password) and `Ri` (the hardware authenticator's WebAuthn PRF output) via `arg2st` to wrap the Master Key with AES-256-GCM. Only this wrapped blob (`encryptedMasterKey: { cipherText, iv, salt }`) is stored on the server; unwrapping it requires **both** your account password (`R0`) and your physical passkey (`Ri`).

### 3. PQC Key Pair (Public & Private Key)
- **Public Key**: Stored in plaintext on the server (`GET /api/accounts/username/{username}`) so peers can encrypt messages/files for you and verify signatures.
- **Private Key**: Decrypted strictly in browser memory from the fetched vault and automatically cleared after 60 seconds, on tab switch, or when the page becomes hidden.

## Installation

### 1. Docker Compose (Recommended)
Prerequisites: Docker and Docker Compose v2.

The container image (`d3vle0/yas-web:latest`) is a lightweight Alpine multi-arch image (`linux/amd64`, `linux/arm64`) and persists the SQLite database in `./data`.

1. Create `docker-compose.yml`
   ```yaml
   services:
     yas-web:
       image: d3vle0/yas-web:latest
       container_name: yas-web
       restart: unless-stopped
       ports:
         - "4000:4000"
       environment:
         # Domain name for WebAuthn passkeys (e.g. example.com in production)
         DOMAIN: localhost
         # Optional; a random 32-byte secret is generated in memory if omitted.
         # JWT_SECRET: change-this-to-a-random-secret-key
       volumes:
         - ./data:/app/data
   ```

2. Start the service (accessible at `http://localhost:4000` by default):
   ```bash
   docker compose up -d
   ```

### 2. Pre-built Binary
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

   *(Optional)* To customize settings, create a `.env` file in the same directory as the binary (see [`.env.example`](.env.example)).

### 3. Manual Build from Source
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

*(Optional)* To customize settings, create a `.env` file in the project root (see [`.env.example`](.env.example)).

*(SQLite database is automatically stored in `./data/yas-web.db`)*
