import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers"
import { defineConfig } from "vitest/config"

export default defineConfig(async () => {
  const migrations = await readD1Migrations("migrations")

  return {
    plugins: [
      cloudflareTest({
        main: "./src/index.ts",
        miniflare: {
          r2Buckets: ["AVATARS"],
          bindings: {
            TEST_MIGRATIONS: migrations,
            ISSUER: "https://auth.pangda.app",
            EMAIL_DELIVERY_MODE: "test",
            BOOTSTRAP_TOKEN: "test-bootstrap-token-with-more-than-32-characters",
          },
        },
        wrangler: { configPath: "./wrangler.toml" },
      }),
    ],
    test: {
      include: ["test/**/*.test.ts"],
      setupFiles: ["./test/apply-migrations.ts"],
      coverage: {
        provider: "istanbul" as const,
        reporter: ["text", "json-summary", "lcov"],
        reportsDirectory: "coverage",
        include: ["src/**/*.ts"],
        exclude: ["src/types/**", "src/**/*.d.ts"],
        thresholds: {
          statements: 65,
          branches: 50,
          functions: 65,
          lines: 65,
        },
      },
    },
  }
})
