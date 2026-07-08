import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    cli: "src/cli.ts",
    index: "src/index.ts",
    permission: "src/engine/permission.ts",
  },
  format: "esm",
  platform: "node",
  target: "node20",
  outDir: "dist",
  clean: true,
  sourcemap: true,
  dts: false,
  splitting: false,
  external: ["better-sqlite3", "@napi-rs/keyring", "ws", "zod", "@modelcontextprotocol/sdk"],
});
