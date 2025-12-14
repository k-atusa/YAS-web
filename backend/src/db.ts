import mongoose from "mongoose";

export async function connectToDatabase(uri: string) {
  if (!uri) {
    throw new Error("Missing MongoDB connection string");
  }

  if (mongoose.connection.readyState === 1) {
    return;
  }

  await mongoose.connect(uri);
  console.log("Connected to MongoDB");
}
