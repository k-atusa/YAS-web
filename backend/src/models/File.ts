import mongoose, { Schema, Document } from "mongoose";

export interface IFile extends Document {
  senderId: string;
  recipientId: string;
  filename: string;
  filePath: string;
  torDomain: string; // Now stores the encrypted Tor domain
  torDomainHash: string; // The hashed Tor domain for lookups
  expiresAt: Date;
  maxDownloads: number;
  downloadCount: number;
}

const fileSchema = new Schema<IFile>(
  {
    senderId: { type: String, required: true },
    recipientId: { type: String, required: true },
    filename: { type: String, required: true },
    filePath: { type: String, required: true },
    torDomain: { type: String, required: true },
    torDomainHash: { type: String, required: true, unique: true },
    maxDownloads: { type: Number, required: true, default: 1, min: 1 },
    downloadCount: { type: Number, required: true, default: 0, min: 0 },
    // MongoDB TTL Index
    expiresAt: { type: Date, required: true, expires: 0 },
  },
  { timestamps: true }
);

export const FileModel = mongoose.model<IFile>("File", fileSchema);
