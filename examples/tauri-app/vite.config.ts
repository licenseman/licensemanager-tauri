import { defineConfig } from "vite";

// Tauri expects a fixed port and fails if it is not available.
export default defineConfig({
	clearScreen: false,
	server: {
		port: 1420,
		strictPort: true,
		watch: { ignored: ["**/src-tauri/**"] },
	},
});
