import mongoose, { Schema, Document } from "mongoose";
import { AccountPayload } from "../types/crypto";

export interface AccountDocument extends Document {
  username: string;
  publicKey: string;
  encryptedPrivateKey: AccountPayload["encryptedPrivateKey"];
  kdf: AccountPayload["kdf"];
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

const EncryptedPrivateKeySchema = new Schema({
  cipherText: { type: String, required: true },
  iv: { type: String, required: true },
  authTag: { type: String, required: false },
});

const KdfSchema = new Schema({
  algorithm: { type: String, enum: ["PBKDF2", "scrypt", "argon2"], required: true },
  salt: { type: String, required: true },
  iterations: { type: Number },
  memoryCost: { type: Number },
  parallelism: { type: Number },
  keyLength: { type: Number },
  hash: { type: String },
});

const AccountSchema = new Schema<AccountDocument>(
  {
    username: { type: String, required: true, unique: true, index: true },
    publicKey: { type: String, required: true },
    encryptedPrivateKey: { type: EncryptedPrivateKeySchema, required: true },
    kdf: { type: KdfSchema, required: true },
    notes: { type: String },
  },
  { timestamps: true }
);

// Force collection name to `keys` to replace previous `accounts` collection.
export const AccountModel = mongoose.model<AccountDocument>("Key", AccountSchema, "keys");
