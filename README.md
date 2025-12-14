# YAS-web

Encrypted-key storage playground. RSA key pairs are generated in the browser, the private key is wrapped with a passphrase-derived AES-GCM key, and only ciphertext plus KDF metadata ever reach the server. A JWT-protected API lets you sync the encrypted blob to MongoDB while keeping the passphrase local.

## Architecture
- Backend: Express + TypeScript + MongoDB (Mongoose). `/api/auth` handles signup/login and issues JWTs; `/api/accounts` stores and fetches encrypted key material. Account writes are guarded by `Authorization: Bearer <token>`.
- Frontend: React + Vite + TypeScript. Generates RSA-4096 pairs, derives AES-GCM keys via PBKDF2 (310k iterations) and can be extended to scrypt/Argon2. Includes a tabbed UI for managing keys, copying the public key, and handling future encrypt/decrypt UX.
- Data shape: `{ username, publicKey, encryptedPrivateKey: { cipherText, iv, authTag? }, kdf: { algorithm, salt, keyLength, iterations?, memoryCost?, parallelism?, hash? }, notes, timestamps }`. Passphrases and plaintext keys never leave the browser.

## Quick start
Prereqs: Node 18+, pnpm/npm/yarn, and MongoDB running locally (default URI `mongodb://localhost:27017/yas-web`).

Backend
1. `cd backend`
2. `cp .env.example .env` and set `MONGODB_URI`, `JWT_SECRET`, `CORS_ORIGIN`
3. `npm install`
4. `npm run dev` (listens on `http://localhost:4000`)

Frontend
1. `cd frontend`
2. `cp .env.example .env` (configure `VITE_API_BASE` if you change the backend origin)
3. `npm install`
4. `npm run dev` (Vite on `http://localhost:5173`)

## Environment variables
- `backend/.env`
  - `MONGODB_URI` – Mongo connection string
  - `PORT` – API port (default 4000)
  - `JWT_SECRET` – signing key for auth tokens (required in prod)
  - `CORS_ORIGIN` – frontend origin allowed by CORS (default `*`)
- `frontend/.env`
  - `VITE_API_BASE` – base URL for API requests (default `http://localhost:4000/api`)

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
  Returns `{ "token": "<jwt>", "user": { "id", "username" } }`. Use the token as a Bearer auth header for account writes.

### Accounts
- `POST /api/accounts` (requires `Authorization: Bearer <jwt>`)
  ```json
  {
    "username": "alice",
    "publicKey": "-----BEGIN PUBLIC KEY-----...",
    "encryptedPrivateKey": {
      "cipherText": "base64",
      "iv": "base64",
      "authTag": "base64" // optional, AES-GCM tag (browser crypto stacks it onto cipherText)
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

## Security notes
- Passphrases stay in the browser; only ciphertext, IV, optional authTag, KDF metadata, username, public key, notes, and timestamps are persisted.
- JWT secret falls back to `dev-secret` only when unset; set a strong `JWT_SECRET` before deploying.
- Consider rate limiting, Argon2/scrypt KDF options, and hardware-backed key storage for production setups.

## Next steps
- Ship the encrypt/decrypt tabs to support hybrid file sharing (AES payload + RSA-OAEP wrapped key).
- Offer user-selectable KDFs (PBKDF2, scrypt, Argon2) with UI guidance on memory/CPU tradeoffs.