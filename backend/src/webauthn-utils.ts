/**
 * WebAuthn utility functions
 * Handles credential registration and authentication without external library
 */

import crypto from "crypto";
import jwt from "jsonwebtoken";

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
 * Create a temporary JWT token for key decryption after WebAuthn auth
 * This token allows the client to decrypt the private key
 */
export function generateDecryptionToken(userId: string, expirySeconds = 300): { token: string; expiresAt: Date } {
  const expiresAt = new Date(Date.now() + expirySeconds * 1000);

  // Get JWT secret (same as requireAuth middleware)
  const secret = process.env.JWT_SECRET || "dev-secret";

  const payload = { sub: userId, type: "decrypt" };
  const token = jwt.sign(payload, secret, { expiresIn: expirySeconds });

  return { token, expiresAt };
}

/**
 * Verify a decryption token (deprecated - use requireAuth middleware instead)
 */
export function verifyDecryptionToken(token: string): { userId: string } | null {
  try {
    const secret = process.env.JWT_SECRET || "dev-secret";
    const payload = jwt.verify(token, secret) as any;
    if (payload.type !== "decrypt") {
      return null;
    }
    return { userId: payload.sub };
  } catch {
    return null;
  }
}
