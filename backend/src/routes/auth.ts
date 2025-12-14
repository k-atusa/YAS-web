import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { UserModel } from "../models/User";

const router = Router();

const signupSchema = z.object({
  username: z.string().min(3),
  password: z
    .string()
    .min(10, "Password must be at least 10 characters")
    .superRefine((val, ctx) => {
      const hasUpper = /[A-Z]/.test(val);
      const hasLower = /[a-z]/.test(val);
      const hasNumber = /[0-9]/.test(val);
      const hasSpecial = /[^A-Za-z0-9]/.test(val);
      if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Password is too weak: include uppercase, lowercase, number, and special character",
          path: ["password"],
        });
      }
    }),
});

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

function signToken(userId: string, username: string) {
  let secret = process.env.JWT_SECRET;
  if (!secret) {
    // Dev fallback to avoid hard failures when env is missing; log so it can be fixed in real deployments.
    console.warn("JWT_SECRET is not set; using insecure dev fallback. Set JWT_SECRET in production.");
    secret = "dev-secret";
  }
  return jwt.sign({ sub: userId, username }, secret, { expiresIn: "1d" });
}

router.post("/signup", async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    const pwdIssue = parsed.error.issues.find((i) => i.path.join(".") === "password");
    if (pwdIssue) {
      return res.status(400).json({ message: pwdIssue.message || "Password is too weak" });
    }
    const first = parsed.error.issues[0];
    return res.status(400).json({ message: first?.message || "Invalid payload" });
  }

  const { username, password } = parsed.data;
  try {
    const existing = await UserModel.findOne({ username }).lean();
    if (existing) {
      return res.status(409).json({ message: "User already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await UserModel.create({ username, passwordHash });
    return res.status(201).json({ id: user.id, username: user.username });
  } catch (error) {
    console.error("Signup failed", error);
    return res.status(500).json({ message: "Failed to sign up" });
  }
});

router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid payload", issues: parsed.error.flatten() });
  }

  const { username, password } = parsed.data;
  try {
    const user = await UserModel.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = signToken(user.id, user.username);
    return res.json({ token, user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error("Login failed", error);
    return res.status(500).json({ message: "Failed to log in" });
  }
});

export default router;
