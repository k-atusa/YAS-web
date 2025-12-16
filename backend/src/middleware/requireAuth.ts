import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthPayload {
  sub?: string;
  username?: string;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthPayload;
}

function resolveSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }

  console.warn("JWT_SECRET is not set; using insecure dev fallback. Set JWT_SECRET in production.");
  return "dev-secret";
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = header.slice("bearer ".length);
  const secret = resolveSecret();

  try {
    const payload = jwt.verify(token, secret) as AuthPayload;
    req.user = payload;
    return next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
}
