import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build is embedded into the Go binary (internal/web); the dev server
// sends API calls to a local `wbft-analyzer serve`.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/web/dist/app",
    emptyOutDir: true,
    // No data: URIs: every file is served under the page's CSP.
    assetsInlineLimit: 0,
  },
  server: { proxy: { "/v1": "http://127.0.0.1:8080" } },
});
