import { Router, Response } from "express";
import { z } from "zod";
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "crypto";
import { AccountModel } from "../models/Account";
import type { AccountPayload } from "../types/crypto";
import { requireAuth, AuthenticatedRequest } from "../middleware/requireAuth";

const router = Router();

function isBase64(str: string) {
	try {
		return Buffer.from(str, "base64").toString("base64") === str.replace(/\s+/g, "");
	} catch {
		return false;
	}
}

function isLength(str: string, expected: number) {
	try {
		return Buffer.from(str, "base64").length === expected;
	} catch {
		return false;
	}
}

const accountSchema: z.ZodType<AccountPayload> = z
	.object({
		username: z.string().min(3),
		publicKey: z.string().min(1),
		encryptedPrivateKey: z.object({
			cipherText: z.string().min(1),
			iv: z.string().min(1),
			authTag: z.string().optional(),
		}),
		kdf: z.object({
			algorithm: z.enum(["PBKDF2", "scrypt", "argon2"]),
			salt: z.string().min(1),
			iterations: z.number().int().positive().optional(),
			memoryCost: z.number().int().positive().optional(),
			parallelism: z.number().int().positive().optional(),
			keyLength: z.number().int().positive().optional(),
			hash: z.string().optional(),
		}),
		notes: z.string().optional(),
	})
	.superRefine((val, ctx) => {
		const { encryptedPrivateKey, kdf } = val;

		if (!isBase64(encryptedPrivateKey.cipherText)) {
			ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["encryptedPrivateKey", "cipherText"], message: "cipherText must be base64" });
		}
		if (!isBase64(encryptedPrivateKey.iv) || !isLength(encryptedPrivateKey.iv, 12)) {
			ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["encryptedPrivateKey", "iv"], message: "iv must be base64 12-byte (AES-GCM)" });
		}
		if (encryptedPrivateKey.authTag && !isBase64(encryptedPrivateKey.authTag)) {
			ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["encryptedPrivateKey", "authTag"], message: "authTag must be base64" });
		}

		if (!isBase64(kdf.salt)) {
			ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "salt"], message: "salt must be base64" });
		}

		if (kdf.algorithm === "PBKDF2") {
			if (!kdf.iterations) {
				ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "iterations"], message: "PBKDF2 requires iterations" });
			}
			if (!kdf.hash) {
				ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "hash"], message: "PBKDF2 requires hash" });
			}
		}

		if (kdf.algorithm === "scrypt") {
			if (!kdf.memoryCost) {
				ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "memoryCost"], message: "scrypt requires memoryCost" });
			}
			if (!kdf.parallelism) {
				ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "parallelism"], message: "scrypt requires parallelism" });
			}
		}

		if (kdf.algorithm === "argon2") {
			if (!kdf.memoryCost) {
				ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "memoryCost"], message: "argon2 requires memoryCost" });
			}
			if (!kdf.parallelism) {
				ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "parallelism"], message: "argon2 requires parallelism" });
			}
		}

		if (!kdf.keyLength) {
			ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kdf", "keyLength"], message: "keyLength is required" });
		}
	});

router.post("/", requireAuth, async (req: AuthenticatedRequest, res) => {
	const parsed = accountSchema.safeParse(req.body);
	if (!parsed.success) {
		return res.status(400).json({ message: "Invalid payload", issues: parsed.error.flatten() });
	}

	const requester = req.user;
	if (requester?.username && requester.username !== parsed.data.username) {
		return res.status(403).json({ message: "Username mismatch" });
	}

	try {
		const doc = await AccountModel.findOneAndUpdate(
			{ username: parsed.data.username },
			parsed.data,
			{
				new: true, // return the updated/new document
				upsert: true, // insert if not existing
				setDefaultsOnInsert: true,
			}
		);

		if (!doc) {
			return res.status(500).json({ message: "Failed to store account" });
		}

		const createdAtMs = doc.createdAt instanceof Date ? doc.createdAt.getTime() : undefined;
		const updatedAtMs = doc.updatedAt instanceof Date ? doc.updatedAt.getTime() : undefined;
		const upserted = Boolean(createdAtMs && updatedAtMs && createdAtMs === updatedAtMs);

		const payload = { id: doc._id?.toString?.() ?? doc.id, createdAt: doc.createdAt, updatedAt: doc.updatedAt, upserted };
		return res.status(upserted ? 201 : 200).json(payload);
	} catch (error) {
		console.error("Failed to store account", error);
		return res.status(500).json({ message: "Failed to store account" });
	}
});

router.get("/username/:username", async (req, res) => {
	try {
		const account = await AccountModel.findOne({ username: req.params.username }).lean();
		if (!account) {
			return res.status(404).json({ message: "Not found" });
		}
		return res.json(sanitize(account));
	} catch (error) {
		console.error("Lookup failed", error);
		return res.status(500).json({ message: "Failed to fetch account" });
	}
});

router.get("/:id", async (req, res) => {
	try {
		const account = await AccountModel.findById(req.params.id).lean();
		if (!account) {
			return res.status(404).json({ message: "Not found" });
		}
		return res.json(sanitize(account));
	} catch (error) {
		console.error("Lookup failed", error);
		return res.status(500).json({ message: "Failed to fetch account" });
	}
});

/**
 * POST /accounts/decrypt
 * Decrypt a stored private key using WebAuthn decryption token
 * Requires authentication (WebAuthn verified)
 */
router.post("/decrypt", requireAuth, async (req: AuthenticatedRequest, res: Response) => {
	console.log("[accounts/decrypt] Request received with user:", req.user);

	const schema = z.object({
		username: z.string().min(1),
	});

	const parsed = schema.safeParse(req.body);
	if (!parsed.success) {
		console.error("[accounts/decrypt] Invalid payload:", parsed.error);
		return res.status(400).json({ message: "Invalid payload" });
	}

	try {
		const userId = req.user?.sub;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const { username } = parsed.data;

		// Find account
		const account = await AccountModel.findOne({ username });
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}

		// Decrypt private key using username as passphrase
		// This uses the same deterministic KDF as frontend
		if (!account.kdf || account.kdf.algorithm !== "PBKDF2") {
			return res.status(400).json({ message: "Only PBKDF2 encryption is supported" });
		}

		try {
			const salt = Buffer.from(account.kdf.salt, "base64");
			const iterations = account.kdf.iterations ?? 310000;
			const keyLength = account.kdf.keyLength ?? 32;
			// Frontend stores hash as "SHA-256", Node.js needs "sha256"
			const rawHash = account.kdf.hash ?? "SHA-256";
			const hash = rawHash.toLowerCase().replace("-", "");

			// Derive key using PBKDF2 (same as frontend deriveStorageKey)
			const aesKey = pbkdf2Sync(Buffer.from(username, "utf-8"), salt, iterations, keyLength, hash);

			// Decrypt AES-GCM
			const iv = Buffer.from(account.encryptedPrivateKey.iv, "base64");
			const rawCipherText = Buffer.from(account.encryptedPrivateKey.cipherText, "base64");

			// Web Crypto AES-GCM appends the 16-byte auth tag to the ciphertext
			// We need to split them for Node.js crypto
			const AUTH_TAG_LENGTH = 16;
			let cipherText: Buffer;
			let authTag: Buffer;

			if (account.encryptedPrivateKey.authTag) {
				// Auth tag stored separately
				cipherText = rawCipherText;
				authTag = Buffer.from(account.encryptedPrivateKey.authTag, "base64");
			} else {
				// Auth tag appended to ciphertext (Web Crypto default)
				cipherText = rawCipherText.subarray(0, rawCipherText.length - AUTH_TAG_LENGTH);
				authTag = rawCipherText.subarray(rawCipherText.length - AUTH_TAG_LENGTH);
			}

			const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
			decipher.setAuthTag(authTag);

			const decrypted = Buffer.concat([
				decipher.update(cipherText),
				decipher.final(),
			]);

			const privateKeyB64 = decrypted.toString("utf-8");

			return res.json({ privateKey: privateKeyB64 });
		} catch (decryptError) {
			console.error("Decryption failed:", decryptError);
			return res.status(400).json({ message: "Decryption failed - invalid credentials or corrupted data" });
		}
	} catch (error) {
		console.error("Decrypt route failed", error);
		return res.status(500).json({ message: "Failed to decrypt private key" });
	}
});

function sanitize(account: any) {
	// Return only fields that are safe to expose back to the client
	return {
		id: account._id?.toString?.() ?? account.id,
		username: account.username,
		publicKey: account.publicKey,
		encryptedPrivateKey: account.encryptedPrivateKey,
		kdf: account.kdf,
		notes: account.notes,
		createdAt: account.createdAt,
		updatedAt: account.updatedAt,
	};
}

export default router;
