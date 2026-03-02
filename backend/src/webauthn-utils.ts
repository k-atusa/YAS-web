/**
 * WebAuthn utility functions
 * Handles credential registration and authentication without external library
 */

import crypto from "crypto";

/**
 * Generate a random challenge for WebAuthn
 */
export function generateChallenge(): string {
  return crypto.randomBytes(32).toString("base64");
}

/**
 * Generate registration options for WebAuthn
 */
export function generateRegistrationOptions(
  username: string,
  userId: string,
  challenge: string
): any {
  return {
    challenge,
    rp: {
      name: "YAS Web",
      id: process.env.WEBAUTHN_RP_ID || "localhost",
    },
    user: {
      id: Buffer.from(userId).toString("base64"),
      name: username,
      displayName: username,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 }, // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    timeout: 60000,
    attestation: "direct",
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "preferred",
    },
  };
}

/**
 * Generate authentication options for WebAuthn
 */
export function generateAuthenticationOptions(challenge: string, allowedCredentials?: Array<{ id: string }>): any {
  return {
    challenge,
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials: allowedCredentials
      ? allowedCredentials.map((cred) => ({
          type: "public-key",
          id: cred.id,
          transports: ["usb", "nfc", "ble", "internal"],
        }))
      : [],
  };
}

/**
 * Verify that a credential ID is valid base64
 */
export function isValidBase64(str: string): boolean {
  try {
    return Buffer.from(str, "base64").toString("base64") === str;
  } catch {
    return false;
  }
}

/**
 * Create a temporary token for key unwrapping after WebAuthn auth
 * This token allows the client to decrypt the private key
 */
export function generateDecryptionToken(userId: string, expirySeconds = 300): { token: string; expiresAt: Date } {
  const expiresAt = new Date(Date.now() + expirySeconds * 1000);
  const payload = JSON.stringify({ sub: userId, type: "decrypt", iat: Date.now(), exp: expiresAt.getTime() });
  const token = Buffer.from(payload).toString("base64");
  return { token, expiresAt };
}

/**
 * Verify a decryption token
 */
export function verifyDecryptionToken(token: string): { userId: string } | null {
  try {
    const payload = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));
    if (payload.type !== "decrypt" || payload.exp < Date.now()) {
      return null;
    }
    return { userId: payload.sub };
  } catch {
    return null;
  }
}
