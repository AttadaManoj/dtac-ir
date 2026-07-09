import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxies /api and /health to the FastAPI backend during local dev so the
// dashboard can just call relative paths without CORS juggling.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        ws: true,
      },
      "/health": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
