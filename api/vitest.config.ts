import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests live outside src/ so the shipped dist/ contains no test code.
    include: ["tests/**/*.test.ts"],
    environment: "node",
    pool: "threads",
  },
});