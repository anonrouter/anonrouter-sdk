import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // This suite needs a fresh child process with its synthetic CA installed
    // before Node starts. The dedicated runner builds and removes that fixture.
    exclude: [...configDefaults.exclude, "test/gateway-bound-client.test.ts"],
  },
});
