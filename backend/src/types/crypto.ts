export type KdfAlgorithm = "PBKDF2" | "scrypt" | "argon2";

export interface KdfParameters {
  algorithm: KdfAlgorithm;
  salt: string; // base64
  iterations?: number; // PBKDF2
  memoryCost?: number; // scrypt/argon2
  parallelism?: number; // scrypt/argon2
  keyLength?: number; // bytes
  hash?: string; // e.g. SHA-256
}

export interface EncryptedPrivateKey {
  cipherText: string; // base64
  iv: string; // base64
  authTag?: string; // base64 (AES-GCM tag if stored separately)
}

export interface AccountPayload {
  username: string;
  publicKey: string;
  encryptedPrivateKey: EncryptedPrivateKey;
  kdf: KdfParameters;
  notes?: string;
}
