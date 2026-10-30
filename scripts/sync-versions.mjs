#!/usr/bin/env node
// Copies the version Changesets wrote to package.json into the crate's
// Cargo.toml, then updates Cargo.lock, so the "Version Packages" PR bumps the
// npm package and the crate together.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));
const manifest = readFileSync("Cargo.toml", "utf8");

// `version = "…"` within the `[package]` table (before the next `[table]` line).
const pattern = /(\[package\](?:\n(?!\[)[^\n]*)*?\nversion\s*=\s*")[^"]*(")/;
if (!pattern.test(manifest)) {
	throw new Error("No [package] version found in Cargo.toml");
}
writeFileSync("Cargo.toml", manifest.replace(pattern, `$1${version}$2`));
execFileSync("cargo", ["update", "--workspace"], { stdio: "inherit" });
console.log(`tauri-plugin-licensemanager set to ${version}`);
