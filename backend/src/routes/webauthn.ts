import { Router, Request, Response } from "express";
import { z } from "zod";
import { UserModel } from "../models/User";
import { requireAuth } from "../middleware/requireAuth";
import {
  generateChallenge,
  generateRegistrationOptions,
  generateAuthenticationOptions,
  generateDecryptionToken,
  isValidBase64,
} from "../webauthn-utils";

const router = Router();

/**
 * POST /webauthn/register-options
 * Get options for WebAuthn credential registration
 * Requires authentication
 */
router.post("/register-options", requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId;
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const challenge = generateChallenge();
    const options = generateRegistrationOptions(user.username, userId, challenge);

    // Store challenge temporarily
    user.webauthnChallenge = challenge;
    await user.save();

    return res.json({ options });
  } catch (error) {
    console.error("WebAuthn register-options failed", error);
    return res.status(500).json({ message: "Failed to generate registration options" });
  }
});

/**
 * POST /webauthn/register-verify
 * Verify WebAuthn credential registration
 * Requires authentication
 */
router.post("/register-verify", requireAuth, async (req: Request, res: Response) => {
  const schema = z.object({
    credentialId: z.string(),
    publicKey: z.string(),
    counter: z.number().int().nonnegative(),
    transports: z.array(z.string()).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  try {
    const userId = (req as any).userId;
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verify credential is valid base64
    if (!isValidBase64(parsed.data.credentialId) || !isValidBase64(parsed.data.publicKey)) {
      return res.status(400).json({ message: "Invalid credential format" });
    }

    // Check if credential already registered
    if (user.webauthnCredentials?.some((c) => c.id === parsed.data.credentialId)) {
      return res.status(409).json({ message: "Credential already registered" });
    }

    // Add credential
    if (!user.webauthnCredentials) {
      user.webauthnCredentials = [];
    }
    user.webauthnCredentials.push({
      id: parsed.data.credentialId,
      publicKey: parsed.data.publicKey,
      counter: parsed.data.counter,
      transports: parsed.data.transports,
    });

    // Clear challenge
    user.webauthnChallenge = undefined;
    await user.save();

    return res.json({ message: "Credential registered successfully" });
  } catch (error) {
    console.error("WebAuthn register-verify failed", error);
    return res.status(500).json({ message: "Failed to verify credential" });
  }
});

/**
 * POST /webauthn/authenticate-options
 * Get options for WebAuthn authentication
 * Requires authentication (user already logged in)
 */
router.post("/authenticate-options", requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId;
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.webauthnCredentials || user.webauthnCredentials.length === 0) {
      return res.status(400).json({ message: "No WebAuthn credentials registered" });
    }

    const challenge = generateChallenge();
    const options = generateAuthenticationOptions(challenge, user.webauthnCredentials);

    // Store challenge temporarily
    user.webauthnChallenge = challenge;
    await user.save();

    return res.json({ options });
  } catch (error) {
    console.error("WebAuthn authenticate-options failed", error);
    return res.status(500).json({ message: "Failed to generate authentication options" });
  }
});

/**
 * POST /webauthn/authenticate-verify
 * Verify WebAuthn authentication and return decryption token
 * Requires authentication (user already logged in)
 */
router.post("/authenticate-verify", requireAuth, async (req: Request, res: Response) => {
  const schema = z.object({
    credentialId: z.string(),
    counter: z.number().int().nonnegative(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  try {
    const userId = (req as any).userId;
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Find matching credential
    const credential = user.webauthnCredentials?.find((c) => c.id === parsed.data.credentialId);
    if (!credential) {
      return res.status(400).json({ message: "Credential not found" });
    }

    // Verify counter is increasing (prevent cloning)
    if (parsed.data.counter <= credential.counter) {
      return res.status(400).json({ message: "Invalid counter (possible cloned authenticator)" });
    }

    // Update counter
    credential.counter = parsed.data.counter;

    // Clear challenge
    user.webauthnChallenge = undefined;
    await user.save();

    // Generate decryption token (valid for 5 minutes)
    const { token, expiresAt } = generateDecryptionToken(userId, 300);

    return res.json({ token, expiresAt });
  } catch (error) {
    console.error("WebAuthn authenticate-verify failed", error);
    return res.status(500).json({ message: "Failed to verify authentication" });
  }
});

/**
 * GET /webauthn/credentials
 * List user's registered WebAuthn credentials
 * Requires authentication
 */
router.get("/credentials", requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId;
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const credentials = (user.webauthnCredentials || []).map((c) => ({
      id: c.id,
      transports: c.transports || [],
      // Don't expose public key in list
    }));

    return res.json({ credentials });
  } catch (error) {
    console.error("WebAuthn credentials list failed", error);
    return res.status(500).json({ message: "Failed to list credentials" });
  }
});

/**
 * DELETE /webauthn/credentials/:credentialId
 * Remove a registered WebAuthn credential
 * Requires authentication
 */
router.delete("/credentials/:credentialId", requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId;
    const { credentialId } = req.params;

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const initialLength = (user.webauthnCredentials || []).length;
    user.webauthnCredentials = (user.webauthnCredentials || []).filter((c) => c.id !== credentialId);

    if (user.webauthnCredentials.length === initialLength) {
      return res.status(404).json({ message: "Credential not found" });
    }

    await user.save();
    return res.json({ message: "Credential removed" });
  } catch (error) {
    console.error("WebAuthn credentials delete failed", error);
    return res.status(500).json({ message: "Failed to remove credential" });
  }
});

export default router;
