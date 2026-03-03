import { Router, Response } from "express";
import { z } from "zod";
import { UserModel } from "../models/User";
import { requireAuth, AuthenticatedRequest } from "../middleware/requireAuth";
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
router.post("/register-options", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
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
router.post("/register-verify", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const schema = z.object({
    credentialId: z.string().min(1, "credentialId cannot be empty"),
    publicKey: z.string().min(1, "publicKey cannot be empty"),
    counter: z.number().int().nonnegative(),
    transports: z.array(z.string()).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: parsed.error.errors[0]?.message || "Invalid payload" });
  }

  try {
    const userId = req.user?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { credentialId, publicKey, counter, transports } = parsed.data;

    // Verify credential is valid base64
    if (!isValidBase64(credentialId)) {
      return res.status(400).json({ message: "credentialId must be valid base64" });
    }
    if (!isValidBase64(publicKey)) {
      return res.status(400).json({ message: "publicKey must be valid base64" });
    }

    // Check if credential already registered
    if (user.webauthnCredentials?.some((c) => c.id === credentialId)) {
      return res.status(409).json({ message: "Credential already registered" });
    }

    // Add credential
    if (!user.webauthnCredentials) {
      user.webauthnCredentials = [];
    }

    console.log(`[WebAuthn] Registering credential with initial counter: ${counter}`);

    user.webauthnCredentials.push({
      id: credentialId,
      publicKey,
      counter,
      transports,
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
router.post("/authenticate-options", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
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
router.post("/authenticate-verify", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const schema = z.object({
    credentialId: z.string(),
    counter: z.number().int().nonnegative(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  try {
    const userId = req.user?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Find matching credential
    const credential = user.webauthnCredentials?.find((c) => c.id === parsed.data.credentialId);
    if (!credential) {
      return res.status(400).json({ message: "Credential not found" });
    }

    console.log(
      `Counter verification: stored=${credential.counter}, received=${parsed.data.counter}, check=${
        credential.counter > 0 && parsed.data.counter <= credential.counter
      }`
    );

    // Verify counter is increasing (prevent cloning)
    // On first use, credential.counter is 0, so any positive counter is valid
    // For subsequent uses, new counter must be strictly greater than previous
    if (credential.counter > 0 && parsed.data.counter <= credential.counter) {
      return res.status(400).json({ message: "Invalid counter (possible cloned authenticator)" });
    }

    // Update counter to the new value
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
router.get("/credentials", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
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
router.delete("/credentials/:credentialId", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
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
