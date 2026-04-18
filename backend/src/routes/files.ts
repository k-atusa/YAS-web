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

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, "../../uploads");

// Ensure uploads dir exists
fs.mkdir(UPLOADS_DIR, { recursive: true }).catch(console.error);

router.use(requireAuth);

router.post("/upload", async (req: any, res) => {
  try {
    const { recipientId, filename, encryptedData, expiresInHours, maxDownloads } = req.body;
    const senderId = req.user?.sub;

    if (!filename || !encryptedData || !expiresInHours) {
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

    const parsedExpiresInHours = Number(expiresInHours);
    const parsedMaxDownloads = Number(maxDownloads ?? 1);
    if (!Number.isFinite(parsedExpiresInHours) || parsedExpiresInHours <= 0) {
      return res.status(400).json({ error: "Invalid expiresInHours" });
    }
    if (!Number.isInteger(parsedMaxDownloads) || parsedMaxDownloads <= 0) {
      return res.status(400).json({ error: "Invalid maxDownloads" });
    }

    const expiresAt = new Date(Date.now() + parsedExpiresInHours * 60 * 60 * 1000);

    // Save actual file instead of DB raw data
    const fileId = new mongoose.Types.ObjectId();
    const filePath = path.join(UPLOADS_DIR, `${fileId.toHexString()}.enc`);
    await fs.writeFile(filePath, encryptedData, "utf8");

    const file = new FileModel({
      _id: fileId,
      senderId,
      recipientId: actualRecipientId,
      filename,
      filePath, // Save physical path
      torDomain,
      expiresAt,
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

router.get("/download/:domain", async (req: any, res) => {
  try {
    const torDomain = `http://${req.params.domain}.onion`;
    const fileDoc = await FileModel.findOne({ torDomain, recipientId: req.user?.sub });
    if (!fileDoc) {
      return res.status(404).json({ error: "File not found or expired" });
    }

    const maxDownloads = Number(fileDoc.maxDownloads ?? 1);
    const downloadCount = Number(fileDoc.downloadCount ?? 0);
    const safeMaxDownloads = Number.isInteger(maxDownloads) && maxDownloads > 0 ? maxDownloads : 1;
    const safeDownloadCount = Number.isFinite(downloadCount) && downloadCount >= 0 ? downloadCount : 0;

    if (safeDownloadCount >= safeMaxDownloads) {
      return res.status(410).json({ error: "Download limit exceeded" });
    }

    fileDoc.maxDownloads = safeMaxDownloads;
    fileDoc.downloadCount = safeDownloadCount + 1;
    await fileDoc.save();
    
    // Read the encrypted payload from disk
    const encryptedData = await fs.readFile(fileDoc.filePath, "utf8");
    
    const file = {
      _id: fileDoc._id,
      senderId: fileDoc.senderId,
      recipientId: fileDoc.recipientId,
      filename: fileDoc.filename,
      torDomain: fileDoc.torDomain,
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
