import { Router } from "express";
import { z } from "zod";
import { ContactModel } from "../models/Contact";
import { requireAuth, AuthenticatedRequest } from "../middleware/requireAuth";

const router = Router();

const contactSchema = z
  .object({
    contactUsername: z.string().min(3).max(64),
    publicKey: z.string().min(1),
    label: z.string().max(120).optional(),
    notes: z.string().max(500).optional(),
  })
  .superRefine((val, ctx) => {
    const trimmed = val.publicKey.trim();
    if (!trimmed.includes("BEGIN PUBLIC KEY") || !trimmed.includes("END PUBLIC KEY")) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["publicKey"], message: "Public key must be a PEM string" });
    }
  });

router.get("/", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!req.user?.sub) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const contacts = await ContactModel.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).lean();
    return res.json(contacts.map(sanitize));
  } catch (error) {
    console.error("Failed to list contacts", error);
    return res.status(500).json({ message: "Failed to list contacts" });
  }
});

router.post("/", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!req.user?.sub || !req.user.username) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const parsed = contactSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid payload", issues: parsed.error.flatten() });
  }

  if (parsed.data.contactUsername === req.user.username) {
    return res.status(400).json({ message: "You cannot add yourself as a contact" });
  }

  try {
    const result = await ContactModel.findOneAndUpdate(
      { ownerId: req.user.sub, contactUsername: parsed.data.contactUsername },
      {
        ownerId: req.user.sub,
        ownerUsername: req.user.username,
        contactUsername: parsed.data.contactUsername,
        publicKey: parsed.data.publicKey.trim(),
        label: parsed.data.label,
        notes: parsed.data.notes,
      },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    if (!result) {
      return res.status(500).json({ message: "Failed to store contact" });
    }

    const created = result.createdAt?.getTime?.() === result.updatedAt?.getTime?.();
    return res.status(created ? 201 : 200).json(sanitize(result));
  } catch (error: any) {
    if (error?.code === 11000) {
      return res.status(409).json({ message: "Contact already exists" });
    }
    console.error("Failed to store contact", error);
    return res.status(500).json({ message: "Failed to store contact" });
  }
});

router.delete("/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!req.user?.sub) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const deleted = await ContactModel.findOneAndDelete({ _id: req.params.id, ownerId: req.user.sub });
    if (!deleted) {
      return res.status(404).json({ message: "Contact not found" });
    }
    return res.status(204).send();
  } catch (error) {
    console.error("Failed to delete contact", error);
    return res.status(500).json({ message: "Failed to delete contact" });
  }
});

function sanitize(contact: any) {
  return {
    id: contact._id?.toString?.() ?? contact.id,
    contactUsername: contact.contactUsername,
    publicKey: contact.publicKey,
    label: contact.label,
    notes: contact.notes,
    createdAt: contact.createdAt,
    updatedAt: contact.updatedAt,
  };
}

export default router;
