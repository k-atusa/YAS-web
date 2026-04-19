import express from "express";
import crypto from "crypto";
import fs from "node:fs/promises";
import path from "node:path";
import mongoose from "mongoose";
import { FileModel } from "../models/File";
import { ContactModel } from "../models/Contact";
import { UserModel } from "../models/User";
import { requireAuth } from "../middleware/requireAuth";
import { createEphemeralHiddenService } from "../tor";
import jwt from "jsonwebtoken";

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, "../../uploads");

const ENCRYPTION_SECRET = process.env.JWT_SECRET || "dev-secret";

function encryptDomain(domain: string, salt: string) {
  const key = crypto.createHash("sha256").update(ENCRYPTION_SECRET + salt).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(domain, "utf8", "base64");
  encrypted += cipher.final("base64");
  const authTag = cipher.getAuthTag().toString("base64");
  return `${iv.toString("base64")}:${authTag}:${encrypted}`;
}

function decryptDomain(encryptedStr: string, salt: string) {
  const parts = encryptedStr.split(":");
  if (parts.length !== 3) return null;
  const [iv, authTag, cipherText] = parts;
  const key = crypto.createHash("sha256").update(ENCRYPTION_SECRET + salt).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(authTag, "base64"));
  try {
    let decrypted = decipher.update(cipherText, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch(e) {
    return null;
  }
}

// Ensure uploads dir exists
fs.mkdir(UPLOADS_DIR, { recursive: true }).catch(console.error);

router.use(requireAuth);

router.post("/upload", async (req: any, res) => {
  try {
    const { recipientId, filename, encryptedData, expiresAt, maxDownloads } = req.body;
    const senderId = req.user?.sub;

    if (!filename || !encryptedData || !expiresAt) {
      return res.status(400).json({ error: "Missing parameters" });
    }

    let actualRecipientId = recipientId;
    if (recipientId) {
      const contact = await ContactModel.findById(recipientId).catch(() => null);
      if (contact) {
        const targetUser = await UserModel.findOne({ username: contact.contactUsername });
        if (targetUser) {
          actualRecipientId = targetUser._id.toHexString();
        } else {
          return res.status(404).json({ error: "Recipient user no longer exists" });
        }
      } else {
        // It might already be a user ID or invalid
        const targetUser = await UserModel.findById(recipientId).catch(() => null);
        if (!targetUser) {
          return res.status(404).json({ error: "Contact or User not found" });
        }
      }
    } else {
      // If no recipient is designated (e.g. password mode), assign it to sender
      actualRecipientId = senderId;
    }

    // Try creating a real Tor Hidden Service pointed to our express port (4000)
    let torDomain;
    try {
      const port = Number(process.env.PORT) || 4000;
      torDomain = await createEphemeralHiddenService(port);
    } catch (e: any) {
      console.warn("Tor Control Port failed, generating random hex fallback.", e.message);
      const randomHex = crypto.randomBytes(28).toString("hex").substring(0, 56);
      torDomain = `http://${randomHex}.onion`;
    }

    const parsedExpiresAt = new Date(expiresAt);
    const parsedMaxDownloads = Number(maxDownloads ?? 1);
    if (isNaN(parsedExpiresAt.getTime())) {
      return res.status(400).json({ error: "Invalid expiresAt" });
    }
    if (parsedExpiresAt <= new Date()) {
      return res.status(400).json({ error: "expiresAt must be in the future" });
    }
    if (!Number.isInteger(parsedMaxDownloads) || parsedMaxDownloads <= 0) {
      return res.status(400).json({ error: "Invalid maxDownloads" });
    }

    const expiresAt_final = parsedExpiresAt;

    // Save actual file instead of DB raw data
    const fileId = new mongoose.Types.ObjectId();
    const filePath = path.join(UPLOADS_DIR, `${fileId.toHexString()}.enc`);
    await fs.writeFile(filePath, encryptedData, "utf8");

    // Encrypt the tor domain for the recipient
    const encryptedTorDomain = encryptDomain(torDomain, actualRecipientId);
    if (!encryptedTorDomain) {
      return res.status(500).json({ error: "Encryption error" });
    }

    const torDomainHash = crypto.createHash("sha256").update(torDomain).digest("hex");

    const file = new FileModel({
      _id: fileId,
      senderId,
      recipientId: actualRecipientId,
      filename,
      filePath, // Save physical path
      torDomain: encryptedTorDomain,
      torDomainHash,
      expiresAt: expiresAt_final,
      maxDownloads: parsedMaxDownloads,
      downloadCount: 0,
    });

    await file.save();
    return res.json({ torDomain, expiresAt, maxDownloads: parsedMaxDownloads });
  } catch (error: any) {
    console.error(error);
    return res.status(500).json({ error: "Failed to upload file" });
  }
});

router.get("/inbox", async (req: any, res) => {
  try {
    const recipientId = req.user?.sub;
    const files = await FileModel.find({ recipientId }).sort({ createdAt: -1 });
    return res.json({ files });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch files" });
  }
});

router.post("/inbox/:id/decrypt-domain", async (req: any, res) => {
  try {
    const { decryptionToken } = req.body;
    if (!decryptionToken) {
      return res.status(400).json({ error: "Missing decryption token" });
    }

    const secret = process.env.JWT_SECRET || "dev-secret";
    const payload = jwt.verify(decryptionToken, secret) as any;
    
    if (payload.type !== "decrypt" || payload.sub !== req.user?.sub) {
      return res.status(403).json({ error: "Invalid decryption token" });
    }

    const fileDoc = await FileModel.findOne({ _id: req.params.id, recipientId: req.user?.sub });
    if (!fileDoc) {
      return res.status(404).json({ error: "File not found" });
    }

    const decryptedTorDomain = decryptDomain(fileDoc.torDomain, fileDoc.recipientId);
    if (!decryptedTorDomain) {
       return res.status(500).json({ error: "Failed to decrypt torDomain." });
    }

    return res.json({ torDomain: decryptedTorDomain });
  } catch(error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
});

router.get("/download/:domain", async (req: any, res) => {
  try {
    const torDomain = `http://${req.params.domain}.onion`;
    const torDomainHash = crypto.createHash("sha256").update(torDomain).digest("hex");
    const fileDoc = await FileModel.findOne({ torDomainHash, recipientId: req.user?.sub });
    if (!fileDoc) {
      return res.status(404).json({ error: "File not found or expired" });
    }

    const maxDownloads = Number(fileDoc.maxDownloads ?? 1);
    const downloadCount = Number(fileDoc.downloadCount ?? 0);
    const safeMaxDownloads = Number.isInteger(maxDownloads) && maxDownloads > 0 ? maxDownloads : 1;
    const safeDownloadCount = Number.isFinite(downloadCount) && downloadCount >= 0 ? downloadCount : 0;

    if (safeDownloadCount >= safeMaxDownloads) {
      await fileDoc.deleteOne();
      await fs.unlink(fileDoc.filePath).catch(() => {});
      return res.status(410).json({ error: "Download limit exceeded" });
    }

    fileDoc.maxDownloads = safeMaxDownloads;
    fileDoc.downloadCount = safeDownloadCount + 1;
    
    const isLimitReached = fileDoc.downloadCount >= fileDoc.maxDownloads;
    if (isLimitReached) {
      await fileDoc.deleteOne();
    } else {
      await fileDoc.save();
    }
    
    // Read the encrypted payload from disk
    const encryptedData = await fs.readFile(fileDoc.filePath, "utf8");
    if (isLimitReached) {
      await fs.unlink(fileDoc.filePath).catch(() => {});
    }
    
    // We send back the decrypted domain so the frontend can display it correctly, or we can just send the generated torDomain
    const file = {
      _id: fileDoc._id,
      senderId: fileDoc.senderId,
      recipientId: fileDoc.recipientId,
      filename: fileDoc.filename,
      torDomain: torDomain,
      expiresAt: fileDoc.expiresAt,
      maxDownloads: safeMaxDownloads,
      downloadCount: fileDoc.downloadCount,
      createdAt: (fileDoc as any).createdAt,
      updatedAt: (fileDoc as any).updatedAt,
      encryptedData
    };

    return res.json({ file });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to download file" });
  }
});

export default router;
