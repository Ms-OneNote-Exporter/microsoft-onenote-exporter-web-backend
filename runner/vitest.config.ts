import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests live outside src/ so the shipped dist/ contains no test code. The
    // same rule as the api, for the same reason: a test helper reachable from the
    // runtime is a debug surface reachable from the runtime.
    include: ["tests/**/*.test.ts"],
    environment: "node",
    pool: "threads",
    // The credential tests drive a real Chromium against a real Microsoft origin
    // with an intercept, and a page load plus a fill is not instant. This is the
    // suite default; individual tests still carry their own timeouts so a genuine
    // hang fails on the test rather than on the file.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
