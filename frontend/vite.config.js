import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // `npm run dev` serves the UI on :5173 and forwards API calls to FastAPI on :8000.
  server: {
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
