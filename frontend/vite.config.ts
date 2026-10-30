import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Dev only: forward API calls to the Go server so the browser sees a single origin (no CORS needed).
    proxy: {
      "/api": "http://localhost:4000",
    },
  },
  build: {
    target: "es2020",
  },
});
