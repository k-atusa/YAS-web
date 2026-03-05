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
    .min(10, "비밀번호는 최소 10자 이상이어야 합니다")
    .superRefine((val, ctx) => {
      const hasUpper = /[A-Z]/.test(val);
      const hasLower = /[a-z]/.test(val);
      const hasNumber = /[0-9]/.test(val);
      const hasSpecial = /[^A-Za-z0-9]/.test(val);
      if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "비밀번호가 약합니다: 대문자, 소문자, 숫자, 특수문자를 포함해주세요",
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
      return res.status(400).json({ message: pwdIssue.message || "비밀번호가 약합니다" });
    }
    const first = parsed.error.issues[0];
    return res.status(400).json({ message: first?.message || "잘못된 요청입니다" });
  }

  const { username, password } = parsed.data;
  try {
    const existing = await UserModel.findOne({ username }).lean();
    if (existing) {
      return res.status(409).json({ message: "이미 존재하는 사용자입니다" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await UserModel.create({ username, passwordHash });
    return res.status(201).json({ id: user.id, username: user.username });
  } catch (error) {
    console.error("Signup failed", error);
    return res.status(500).json({ message: "회원가입에 실패했습니다" });
  }
});

router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "잘못된 요청입니다", issues: parsed.error.flatten() });
  }

  const { username, password } = parsed.data;
  try {
    const user = await UserModel.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다" });
    }

    const token = signToken(user.id, user.username);
    return res.json({ token, user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error("Login failed", error);
    return res.status(500).json({ message: "로그인에 실패했습니다" });
  }
});

export default router;
