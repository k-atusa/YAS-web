import mongoose, { Schema, Document } from "mongoose";

export interface WebAuthnCredential {
  id: string; // credentialId (base64)
  publicKey: string; // public key (base64)
  counter: number; // signature counter
  transports?: string[]; // USB, BLE, NFC, etc.
}

export interface UserDocument extends Document {
  username: string;
  passwordHash: string;
  webauthnCredentials?: WebAuthnCredential[];
  webauthnChallenge?: string; // temporary challenge for registration/authentication
  createdAt: Date;
  updatedAt: Date;
}

const WebAuthnCredentialSchema = new Schema({
  id: { type: String, required: true },
  publicKey: { type: String, required: true },
  counter: { type: Number, required: true, default: 0 },
  transports: { type: [String] },
});

const UserSchema = new Schema<UserDocument>(
  {
    username: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    webauthnCredentials: { type: [WebAuthnCredentialSchema], default: [] },
    webauthnChallenge: { type: String },
  },
  { timestamps: true }
);

export const UserModel = mongoose.model<UserDocument>("User", UserSchema);
