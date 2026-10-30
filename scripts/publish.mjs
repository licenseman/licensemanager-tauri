#!/usr/bin/env node
// Publishes the crate to crates.io unless this version is already there, so a
// failed release can be re-run. `changeset publish` then publishes npm, tags
// and creates the GitHub release: crate first, npm last.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const CRATE = "tauri-plugin-licensemanager";
const { version } = JSON.parse(readFileSync("package.json", "utf8"));

const res = await fetch(
	`https://crates.io/api/v1/crates/${CRATE}/${encodeURIComponent(version)}`,
	{
		headers: {
			"User-Agent": `${CRATE}-release (https://github.com/licenseman/licensemanager-tauri)`,
		},
	},
);

if (res.status === 200) {
	console.log(`${CRATE}@${version} is already on crates.io, skipping`);
} else if (res.status === 404) {
	execFileSync("cargo", ["publish", "-p", CRATE, "--locked"], {
		stdio: "inherit",
	});
} else {
	throw new Error(`crates.io answered ${res.status} for ${CRATE}@${version}`);
}
