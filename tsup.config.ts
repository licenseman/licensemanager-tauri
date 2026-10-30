import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["guest-js/index.ts"],
	outDir: "dist-js",
	format: ["esm", "cjs"],
	dts: true,
	sourcemap: true,
	clean: true,
	target: "es2021",
	platform: "browser",
	external: [/^@tauri-apps\/api/],
});
