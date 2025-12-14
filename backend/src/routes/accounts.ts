import { Router, Request, Response, NextFunction } from "express";
import { z } from "zod";
import { AccountModel } from "../models/Account";
import type { AccountPayload } from "../types/crypto";
import jwt from "jsonwebtoken";

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

function requireAuth(req: Request, res: Response, next: NextFunction) {
	const header = req.headers.authorization;
	if (!header || !header.toLowerCase().startsWith("bearer ")) {
		return res.status(401).json({ message: "Unauthorized" });
	}

	const token = header.slice("bearer ".length);
	let secret = process.env.JWT_SECRET;
	if (!secret) {
		console.warn("JWT_SECRET is not set; using insecure dev fallback. Set JWT_SECRET in production.");
		secret = "dev-secret";
	}

	try {
		const payload = jwt.verify(token, secret) as { sub?: string; username?: string };
		(req as any).user = payload;
		return next();
	} catch (error) {
		return res.status(401).json({ message: "Invalid token" });
	}
}

router.post("/", requireAuth, async (req, res) => {
	const parsed = accountSchema.safeParse(req.body);
	if (!parsed.success) {
		return res.status(400).json({ message: "Invalid payload", issues: parsed.error.flatten() });
	}

	const requester = (req as any).user as { username?: string };
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
