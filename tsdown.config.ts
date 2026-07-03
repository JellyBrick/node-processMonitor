import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["./src/index.ts"],
  format: ["esm", "cjs"],
  platform: "node",
  target: "es2020",
  dts: true,
  shims: true,
  clean: true,
});
