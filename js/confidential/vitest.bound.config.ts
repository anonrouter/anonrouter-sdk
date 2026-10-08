import { defineConfig } from "vitest/config";
export default defineConfig({
  cacheDir: new URL("../../.bound-client-vite-cache", import.meta.url).pathname,
  test: { include: ["test/**/*.test.ts"], environment: "node", testTimeout: 10000, hookTimeout: 10000 },
});
