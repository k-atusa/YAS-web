import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import fs from "node:fs";
import path from "node:path";
import accountsRouter from "./routes/accounts";
import authRouter from "./routes/auth";
import contactsRouter from "./routes/contacts";
import filesRouter from "./routes/files";
import webauthnRouter from "./routes/webauthn";
import { connectToDatabase } from "./db";
import { cleanupOrphanedFiles } from "./cleanup";

const app = express();
const port = Number(process.env.PORT) || 4000;
const mongoUri = process.env.MONGODB_URI || "mongodb://localhost:27017/yas-web";
const corsOrigin = process.env.CORS_ORIGIN || "*";

app.use(helmet());
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(morgan("dev"));

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/api/auth", authRouter);
app.use("/api/accounts", accountsRouter);
app.use("/api/contacts", contactsRouter);
app.use("/api/files", filesRouter);
app.use("/api/webauthn", webauthnRouter);

const resolvedFrontendDir = path.resolve(process.env.FRONTEND_DIST || path.join(process.cwd(), "public"));
const fallbackFrontendDir = path.resolve(path.join(process.cwd(), "../frontend/dist"));
const finalFrontendDir = fs.existsSync(resolvedFrontendDir) ? resolvedFrontendDir : fallbackFrontendDir;

if (fs.existsSync(finalFrontendDir)) {
  app.use(express.static(finalFrontendDir));

  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api/")) {
      return next();
    }
    res.sendFile(path.join(finalFrontendDir, "index.html"));
  });
} else {
  console.warn(`Frontend assets not found at ${resolvedFrontendDir} or ${fallbackFrontendDir}. Serving API only.`);
}

async function start() {
  try {
    await connectToDatabase(mongoUri);
    
    // Start background cleaner every 5 minutes to remove expired files
    setInterval(cleanupOrphanedFiles, 5 * 60 * 1000);
    cleanupOrphanedFiles(); // initial run

    app.listen(port, () => {
      console.log(`API server listening on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Failed to start server", error);
    process.exit(1);
  }
}

start();
