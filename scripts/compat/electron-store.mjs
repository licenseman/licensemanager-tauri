#!/usr/bin/env node
// Cross-SDK storage compatibility check with @licenseman/electron.
//
//   node scripts/compat/electron-store.mjs
//     Installs @licenseman/electron (without optional deps, so it stores in
//     files only), lets it create an install in $COMPAT_DIR/electron/store and
//     writes the fingerprint it computed to $COMPAT_DIR/electron/expected.json.
//     The ignored Rust test `compat_with_electron` then reads the same store.
//
//   node scripts/compat/electron-store.mjs read <dir>
//     Opens <dir> (written by the Rust SDK) with the Electron SDK and prints
//     `{ fingerprint, licenseKey }` as JSON. Called by the Rust test.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const PRODUCT_ID = "x7Kp2QaZ";
const MACHINE = "compat-machine";
const ELECTRON_SDK_VERSION = process.env.ELECTRON_SDK_VERSION ?? "1.1.0";

const compatDir = resolve(
	process.env.COMPAT_DIR ?? join(tmpdir(), "lm-compat"),
);
const nodeDir = join(compatDir, "node");

function loadElectronSdk() {
	const entry = join(nodeDir, "node_modules", "@licenseman", "electron");
	if (!existsSync(entry)) {
		mkdirSync(nodeDir, { recursive: true });
		writeFileSync(join(nodeDir, "package.json"), '{ "private": true }\n');
		execFileSync(
			process.platform === "win32" ? "npm.cmd" : "npm",
			[
				"install",
				"--no-save",
				"--no-audit",
				"--no-fund",
				"--omit=optional",
				"--legacy-peer-deps",
				`@licenseman/electron@${ELECTRON_SDK_VERSION}`,
			],
			{
				cwd: nodeDir,
				stdio: ["ignore", "inherit", "inherit"],
				shell: process.platform === "win32",
			},
		);
	}
	return createRequire(join(nodeDir, "package.json"))("@licenseman/electron");
}

async function open(storeDir) {
	const { LicenseManager } = loadElectronSdk();
	return new LicenseManager({
		productId: PRODUCT_ID,
		// Never used: no key is validated.
		publicKey: "unused",
		fingerprint: MACHINE,
		version: "1.0.0",
		apiBaseUrl: "http://127.0.0.1:9",
		storageDirs: [storeDir],
	});
}

if (process.argv[2] === "read") {
	const manager = await open(resolve(process.argv[3]));
	const result = {
		fingerprint: await manager.getFingerprint(),
		licenseKey: manager.getLicenseKey(),
	};
	manager.dispose();
	process.stdout.write(`${JSON.stringify(result)}\n`);
	process.exit(0);
}

const storeDir = join(compatDir, "electron", "store");
mkdirSync(storeDir, { recursive: true });
const manager = await open(storeDir);
const fingerprint = await manager.getFingerprint();
manager.dispose();
const expected = {
	productId: PRODUCT_ID,
	machine: MACHINE,
	storeDir,
	fingerprint,
};
writeFileSync(
	join(compatDir, "electron", "expected.json"),
	`${JSON.stringify(expected, null, 2)}\n`,
);
console.log(`Electron fingerprint: ${fingerprint}`);
process.exit(0);
