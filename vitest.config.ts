import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test-js/**/*.test.ts"],
		environment: "jsdom",
		coverage: {
			provider: "v8",
			include: ["guest-js/**/*.ts"],
			reporter: ["text", "lcov", "json-summary"],
			thresholds: {
				lines: 80,
				functions: 80,
				branches: 80,
				statements: 80,
			},
		},
	},
});
