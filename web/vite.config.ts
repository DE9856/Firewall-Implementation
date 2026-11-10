import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is served by PyWall's own Python server (firewall/server.py).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../firewall/web", emptyOutDir: true, assetsInlineLimit: 0 },
  server: { proxy: { "/api": "http://127.0.0.1:8080" } },
});
