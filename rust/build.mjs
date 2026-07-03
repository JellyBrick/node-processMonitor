// Build helper (dev-time only): compiles the Rust N-API addon and copies the
// artifact into lib/dist with the historical naming convention.
//
// usage: node rust/build.mjs [x64] [ia32] [arm64]

import { execSync } from "node:child_process";
import { copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const TARGETS = {
  x64: { triple: "x86_64-pc-windows-msvc", dist: "processMonitor.x64.node" },
  ia32: { triple: "i686-pc-windows-msvc", dist: "processMonitor.x86.node" },
  arm64: { triple: "aarch64-pc-windows-msvc", dist: "processMonitor.arm64.node" },
};

const requested = process.argv.slice(2);
if (requested.length === 0) requested.push("x64");

for (const arch of requested) {
  const target = TARGETS[arch];
  if (!target) {
    console.error(`Unknown arch "${arch}". Expected one of: ${Object.keys(TARGETS).join(", ")}`);
    process.exit(1);
  }

  console.log(`\n=== building ${arch} (${target.triple}) ===`);
  execSync(`cargo build --release --target ${target.triple}`, {
    cwd: __dirname,
    stdio: "inherit",
  });

  const built = join(__dirname, "target", target.triple, "release", "wql_process_monitor.dll");
  const dist = join(__dirname, "..", "lib", "dist", target.dist);
  copyFileSync(built, dist);
  console.log(`=> ${dist}`);
}
