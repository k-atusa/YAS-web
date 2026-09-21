# YAS-web

Encrypted-key storage playground and secure messaging/file-sharing platform. Asymmetric key pairs (Curve448, Hybrid PQC) are generated in the browser, private keys are wrapped with a passphrase-derived AES-GCM key (PBKDF2), and only ciphertext plus KDF metadata ever reach the server. Includes WebAuthn (FIDO2 passkey) hardware-backed key decryption, Opsec YAS2 hybrid file/message encryption via USAG-lib, and ephemeral Tor Hidden Service file transfers.

## Architecture
- Backend: Express + TypeScript + MongoDB (Mongoose). Handles user auth and JWT issuance (`/api/auth`), encrypted key material storage and WebAuthn decryption (`/api/accounts`), address book management (`/api/contacts`), Tor ephemeral file sharing (`/api/files`), and WebAuthn credential verification (`/api/webauthn`). Writes and sensitive reads are guarded by `Authorization: Bearer <token>`.
- Frontend: React + Vite + TypeScript. Generates Curve448 (`ecc1`) and Hybrid PQC (`pqc1`) key pairs, derives AES-GCM keys via PBKDF2 (310k iterations), and performs Opsec YAS2 symmetric (AES-GCM) and password-based (Argon2id, SHA-3) encryption via USAG-lib with ZIP/TAR packing. Includes a tabbed UI for Keys (with WebAuthn), Contacts, Encrypt (file/message encryption & Tor dispatch), and Messages (inbox & decryption).
- Data shape: `{ username, publicKey, encryptedPrivateKey: { cipherText, iv, authTag? }, kdf: { algorithm, salt, keyLength, iterations?, memoryCost?, parallelism?, hash? }, notes, timestamps }`. Passphrases and plaintext keys never leave the browser.

## Quick start
Prereqs: Node 18+, pnpm/npm/yarn, and MongoDB running locally (default URI `mongodb://localhost:27017/yas-web`).

Backend
1. `cd backend`
2. `cp .env.example .env` and set `MONGODB_URI`, `PORT`, `JWT_SECRET`, `CORS_ORIGIN`, `WEBAUTHN_RP_ID`
3. `npm install`
4. `npm run dev` (listens on `http://localhost:7001` or configured port)

Frontend
1. `cd frontend`
2. `cp .env.example .env` (configure `VITE_API_BASE_URL` if you change the backend origin)
3. `npm install`
4. `npm run dev` (Vite on `http://localhost:5173`)

Docker Compose (Alternative)
- `docker compose up -d` (starts MongoDB, backend on `:7001`, frontend on `:4000`)

## Environment variables
- `backend/.env`
  - `MONGODB_URI` – Mongo connection string (default `mongodb://localhost:27017/yas-web`)
  - `PORT` – API port (default `7001` in .env.example, fallback `4000`)
  - `JWT_SECRET` – signing key for auth tokens (required in prod)
  - `CORS_ORIGIN` – frontend origin allowed by CORS (default `http://localhost:5173`)
  - `WEBAUTHN_RP_ID` – WebAuthn Relying Party ID (default `localhost`)
- `frontend/.env`
  - `VITE_API_BASE_URL` – base URL for API requests (default `http://localhost:7001/api`)

## API

### Auth
- `POST /api/auth/signup`
  ```jsonc
  { "username": "alice", "password": "StrongP@ssw0rd" }
  ```
  Creates the user after strength validation (>=10 chars, upper/lower/number/symbol).

- `POST /api/auth/login`
  ```jsonc
  { "username": "alice", "password": "StrongP@ssw0rd" }
  ```
  Returns `{ "token": "<jwt>", "user": { "id", "username" } }`. Use the token as a Bearer auth header for protected routes.

### Accounts
- `POST /api/accounts` (requires `Authorization: Bearer <jwt>`)
  ```json
  {
    "username": "alice",
    "publicKey": "base64-or-pem-public-key",
    "encryptedPrivateKey": {
      "cipherText": "base64",
      "iv": "base64",
      "authTag": "base64" // optional, AES-GCM tag
    },
    "kdf": {
      "algorithm": "PBKDF2",
      "salt": "base64",
      "iterations": 310000,
      "keyLength": 32,
      "hash": "SHA-256"
    },
    "notes": "optional text"
  }
  ```
  Upserts by `username`. Returns `{ id, createdAt, updatedAt, upserted }` with `201 Created` for first write and `200 OK` for updates.

- `GET /api/accounts/username/:username`
- `GET /api/accounts/:id`

Both read endpoints return the sanitized record (public key + encrypted blob + metadata). Private material stays encrypted.

- `POST /api/accounts/decrypt` (requires `Authorization: Bearer <jwt>`)
  Decrypts stored private key with verified authorization token.

### Contacts
- `GET /api/contacts` (requires `Authorization: Bearer <jwt>`)
  Returns the user's saved contact list with dynamically updated public keys.
- `POST /api/contacts` (requires `Authorization: Bearer <jwt>`)
  Adds or updates a contact `{ contactUsername, publicKey?, label?, notes? }`.
- `DELETE /api/contacts/:id` (requires `Authorization: Bearer <jwt>`)
  Removes a contact by ID.

### Files
- `POST /api/files/upload` (requires `Authorization: Bearer <jwt>`)
  Uploads encrypted payload `{ recipientId?, filename, encryptedData, expiresAt, maxDownloads }`, stores physical file, and creates an ephemeral Tor hidden service (`.onion` domain).
- `GET /api/files/inbox` (requires `Authorization: Bearer <jwt>`)
  Lists incoming files for the authenticated recipient.
- `POST /api/files/inbox/:id/decrypt-domain` (requires `Authorization: Bearer <jwt>`)
  Decrypts the Tor `.onion` domain using a WebAuthn-issued decryption token.
- `GET /api/files/download/:domain` (requires `Authorization: Bearer <jwt>`)
  Downloads the encrypted file payload, decrementing download count and deleting when limits are reached.
- `GET /` (with `.onion` Host header)
  Direct download endpoint when accessed through the Tor network.

### WebAuthn
- `POST /api/webauthn/register-options` (requires `Authorization: Bearer <jwt>`)
  Generates challenge options for registering a FIDO2 passkey/authenticator.
- `POST /api/webauthn/register-verify` (requires `Authorization: Bearer <jwt>`)
  Verifies and stores WebAuthn credential `{ credentialId, publicKey, counter, transports? }`.
- `POST /api/webauthn/authenticate-options` (requires `Authorization: Bearer <jwt>`)
  Generates authentication challenge for registered credentials.
- `POST /api/webauthn/authenticate-verify` (requires `Authorization: Bearer <jwt>`)
  Verifies assertion signature and counter, returning a short-lived decryption token.
- `GET /api/webauthn/credentials` (requires `Authorization: Bearer <jwt>`)
  Lists user's registered WebAuthn credentials.
- `DELETE /api/webauthn/credentials/:credentialId` (requires `Authorization: Bearer <jwt>`)
  Removes a registered WebAuthn credential.

## Security notes
- Passphrases and raw private keys stay in the browser; only wrapped ciphertext, IV, optional authTag, KDF metadata, username, public key, notes, and timestamps are persisted.
- WebAuthn (FIDO2) counter verification prevents authenticator cloning, and decryption tokens are short-lived (5 minutes).
- Ephemeral Tor Hidden Services allow anonymous payload transport with expiration and download count limits (automatic cleanup upon threshold or expiration).
- JWT secret falls back to `dev-secret` only when unset; set a strong `JWT_SECRET` before deploying.

## Next steps
- Optimize Tor hidden service startup latency and onion socket connection pooling.
- Extend post-quantum hybrid algorithm choices and hardware token integrations.
- Implement real-time encrypted inbox notification websockets.