import type { AccountPayload, EncryptedPrivateKey, KdfParameters } from "./types";

const encoder = new TextEncoder();

function toBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function toArrayBufferFromString(data: string): ArrayBuffer {
  return encoder.encode(data);
}

async function exportKey(key: CryptoKey, format: "spki" | "pkcs8"): Promise<string> {
  const exported = await crypto.subtle.exportKey(format, key);
  const base64 = toBase64(exported);
  const type = format === "spki" ? "PUBLIC" : "PRIVATE";
  const wrapped = base64.match(/.{1,64}/g)?.join("\n") || base64;
  return `-----BEGIN ${type} KEY-----\n${wrapped}\n-----END ${type} KEY-----`;
}

export async function generateRsaKeyPair(): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKeyPem = await exportKey(keyPair.publicKey, "spki");
  const privateKeyPem = await exportKey(keyPair.privateKey, "pkcs8");
  return { publicKeyPem, privateKeyPem };
}

async function deriveKey(passphrase: string, salt: Uint8Array, iterations = 310000, keyLength = 32): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey("raw", toArrayBufferFromString(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: keyLength * 8 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptPrivateKey(privateKeyPem: string, passphrase: string): Promise<{
  encryptedPrivateKey: EncryptedPrivateKey;
  kdf: KdfParameters;
}> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 310000;
  const keyLength = 32;

  const aesKey = await deriveKey(passphrase, salt, iterations, keyLength);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    toArrayBufferFromString(privateKeyPem)
  );

  const encryptedPrivateKey: EncryptedPrivateKey = {
    cipherText: toBase64(cipherBuffer),
    iv: toBase64(iv.buffer),
  };

  const kdf: KdfParameters = {
    algorithm: "PBKDF2",
    salt: toBase64(salt.buffer),
    iterations,
    keyLength,
    hash: "SHA-256",
  };

  return { encryptedPrivateKey, kdf };
}

export async function buildAccountPayload(
  username: string,
  passphrase: string,
  publicKeyPem: string,
  privateKeyPem: string,
  notes?: string
): Promise<AccountPayload> {
  const { encryptedPrivateKey, kdf } = await encryptPrivateKey(privateKeyPem, passphrase);

  return {
    username,
    publicKey: publicKeyPem,
    encryptedPrivateKey,
    kdf,
    notes,
  };
}
