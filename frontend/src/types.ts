export type KdfAlgorithm = "PBKDF2" | "scrypt" | "argon2";

export interface KdfParameters {
  algorithm: KdfAlgorithm;
  salt: string;
  iterations?: number;
  memoryCost?: number;
  parallelism?: number;
  keyLength?: number;
  hash?: string;
}

export interface EncryptedPrivateKey {
  cipherText: string;
  iv: string;
  authTag?: string;
}

export interface AccountPayload {
  username: string;
  publicKey: string;
  encryptedPrivateKey: EncryptedPrivateKey;
  kdf: KdfParameters;
  notes?: string;
}

export interface AccountRecord extends AccountPayload {
  id: string;
  createdAt?: string;
  updatedAt?: string;
}
