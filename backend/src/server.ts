import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import accountsRouter from "./routes/accounts";
import authRouter from "./routes/auth";
import { connectToDatabase } from "./db";

const app = express();
const port = Number(process.env.PORT) || 4000;
const mongoUri = process.env.MONGODB_URI || "mongodb://localhost:27017/yas-web";
const corsOrigin = process.env.CORS_ORIGIN || "*";

app.use(helmet());
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/api/auth", authRouter);
app.use("/api/accounts", accountsRouter);

async function start() {
  try {
    await connectToDatabase(mongoUri);
    app.listen(port, () => {
      console.log(`API server listening on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Failed to start server", error);
    process.exit(1);
  }
}

start();
