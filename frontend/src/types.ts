export type KdfAlgorithm = "arg2st" | "arg2st-prf";

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

export interface AccountRecord {
  id: string;
  username: string;
  publicKey: string;
  hasPrivateKey?: boolean;
  encryptedPrivateKey?: EncryptedPrivateKey;
  kdf?: KdfParameters;
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface AccountVault {
  username: string;
  publicKey: string;
  encryptedPrivateKey: EncryptedPrivateKey;
  kdf: KdfParameters;
}

export interface ContactPayload {
  contactUsername: string;
  publicKey: string;
  label?: string;
  notes?: string;
}

export interface ContactRecord extends ContactPayload {
  id: string;
  createdAt?: string;
  updatedAt?: string;
}
