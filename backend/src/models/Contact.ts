import mongoose, { Schema, Document } from "mongoose";

export interface ContactDocument extends Document {
  ownerId: string;
  ownerUsername: string;
  contactUsername: string;
  publicKey: string;
  label?: string;
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

const ContactSchema = new Schema<ContactDocument>(
  {
    ownerId: { type: String, required: true, index: true },
    ownerUsername: { type: String, required: true },
    contactUsername: { type: String, required: true },
    publicKey: { type: String, required: true },
    label: { type: String },
    notes: { type: String },
  },
  { timestamps: true }
);

ContactSchema.index({ ownerId: 1, contactUsername: 1 }, { unique: true });

export const ContactModel = mongoose.model<ContactDocument>("Contact", ContactSchema);
