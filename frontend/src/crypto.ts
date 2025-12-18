import type { AccountPayload, EncryptedPrivateKey, KdfParameters } from "./types";

const encoder = new TextEncoder();

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000; // prevent call stack overflow for large buffers
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    // apply handles typed arrays without spreading the entire buffer at once
    binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return btoa(binary);
}

function fromBase64(base64: string): ArrayBuffer {
  const normalized = base64.replace(/[^A-Za-z0-9+/=]/g, "");
  const binary = atob(normalized);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function toArrayBufferFromString(data: string): ArrayBuffer {
  return encoder.encode(data);
}

function pemToArrayBuffer(pem: string, type: "PUBLIC" | "PRIVATE" = "PUBLIC"): ArrayBuffer {
  const normalized = pem.replace(/\r/g, "");
  const headerRegex = new RegExp(`-*\\s*BEGIN\\s+${type}\\s+KEY\\s*-*`, "i");
  const footerRegex = new RegExp(`-*\\s*END\\s+${type}\\s+KEY\\s*-*`, "i");
  const headerMatch = headerRegex.exec(normalized);
  const startIndex = headerMatch ? headerMatch.index + headerMatch[0].length : 0;
  const afterHeader = normalized.slice(startIndex);
  const footerMatch = footerRegex.exec(afterHeader);
  const bodySection = footerMatch ? afterHeader.slice(0, footerMatch.index) : afterHeader;
  const base64 = bodySection.replace(/[^A-Za-z0-9+/=]/g, "");
  return fromBase64(base64);
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

export async function importPublicKeyFromPem(pem: string): Promise<CryptoKey> {
  const buffer = pemToArrayBuffer(pem, "PUBLIC");
  return crypto.subtle.importKey(
    "spki",
    buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
}

export async function encryptForPublicKey(data: ArrayBuffer, publicKeyPem: string): Promise<{
  cipherText: string;
  iv: string;
  encryptedKey: string;
}> {
  const publicKey = await importPublicKeyFromPem(publicKeyPem);
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, data);
  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const encryptedKeyBuffer = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAesKey);

  return {
    cipherText: toBase64(cipherBuffer),
    iv: toBase64(iv.buffer),
    encryptedKey: toBase64(encryptedKeyBuffer),
  };
}

export function encodeUtf8(data: string): ArrayBuffer {
  return toArrayBufferFromString(data);
}
