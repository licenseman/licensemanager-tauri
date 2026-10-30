import { emit } from "@tauri-apps/api/event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as sdk from "../guest-js/index";
import { LicenseError } from "../guest-js/index";

/** The API by name, for table-driven tests. */
const api: Record<string, unknown> = { ...sdk };

type Handler = (args: Record<string, unknown>) => unknown;

/** Mock the plugin's commands; records every call. */
function mockCommands(handlers: Record<string, Handler>) {
	const calls: Array<{ cmd: string; args: unknown }> = [];
	mockIPC(
		(cmd, args) => {
			calls.push({ cmd, args });
			const name = cmd.replace(/^plugin:licensemanager\|/, "");
			const handler = handlers[name];
			if (!handler) throw new Error(`unexpected command ${cmd}`);
			return handler((args ?? {}) as Record<string, unknown>);
		},
		{ shouldMockEvents: true },
	);
	return calls;
}

afterEach(() => {
	clearMocks();
});

describe("public entry point", () => {
	it("exports the SDK name and the API", () => {
		expect(sdk.SDK_NAME).toBe("@licenseman/tauri");
		expect(sdk.STATE_CHANGED_EVENT).toBe("licensemanager://state-changed");
		for (const name of [
			"getState",
			"ready",
			"getLicense",
			"setLicenseKey",
			"refresh",
			"getOfflineState",
			"getLatestAllowedVersion",
			"getPortalUrl",
			"isClockTampered",
			"getLicenseKeyHint",
			"getLicenseKey",
			"getFingerprint",
			"onStateChange",
			"watchLicense",
		] as const) {
			expect(typeof api[name]).toBe("function");
		}
		expect(typeof LicenseError).toBe("function");
	});
});

describe("commands", () => {
	it.each([
		["getState", "get_state", "ACTIVE"],
		["ready", "ready", "MISSING_KEY"],
		["refresh", "refresh", "EXPIRED"],
		[
			"getPortalUrl",
			"get_portal_url",
			"https://app.licensemanager.dev/portal/p",
		],
		["isClockTampered", "is_clock_tampered", true],
		["getLicenseKeyHint", "get_license_key_hint", "B3JDF"],
		["getLicenseKey", "get_license_key", null],
		["getFingerprint", "get_fingerprint", "a:b:p"],
	] as const)("%s invokes %s", async (fn, command, value) => {
		const calls = mockCommands({ [command]: () => value });
		expect(await (api[fn] as () => Promise<unknown>)()).toBe(value);
		expect(calls.map((c) => c.cmd)).toEqual([
			`plugin:licensemanager|${command}`,
		]);
	});

	it("sends the key to set_license_key", async () => {
		const calls = mockCommands({ set_license_key: () => "ACTIVE" });
		expect(await sdk.setLicenseKey(" KEY ")).toBe("ACTIVE");
		expect(calls[0]?.args).toEqual({ key: " KEY " });
	});

	it("converts validUntil to a Date", async () => {
		mockCommands({
			get_offline_state: () => ({
				mode: "offline",
				validUntil: 1_767_225_600_000,
				remainingMs: 42,
			}),
		});
		expect(await sdk.getOfflineState()).toEqual({
			mode: "offline",
			validUntil: new Date(1_767_225_600_000),
			remainingMs: 42,
		});
	});

	it("keeps a null validUntil and the online mode", async () => {
		let dto: unknown = { mode: "offline", validUntil: null, remainingMs: 0 };
		mockCommands({ get_offline_state: () => dto });
		expect(await sdk.getOfflineState()).toEqual({
			mode: "offline",
			validUntil: null,
			remainingMs: 0,
		});
		dto = { mode: "online" };
		expect(await sdk.getOfflineState()).toEqual({ mode: "online" });
	});

	it.each([
		[{}, undefined],
		[{ latestAllowedVersion: null }, null],
		[{ latestAllowedVersion: "2.3.1" }, "2.3.1"],
	])("getLatestAllowedVersion maps %j to %j", async (dto, expected) => {
		mockCommands({ get_latest_allowed_version: () => dto });
		expect(await sdk.getLatestAllowedVersion()).toBe(expected);
	});

	it("getLicense converts the snapshot", async () => {
		mockCommands({
			get_license: () => ({
				state: "VERSION_NOT_ALLOWED",
				offline: { mode: "offline", validUntil: 1000, remainingMs: 5 },
				latestAllowedVersion: null,
			}),
		});
		expect(await sdk.getLicense()).toEqual({
			state: "VERSION_NOT_ALLOWED",
			offline: { mode: "offline", validUntil: new Date(1000), remainingMs: 5 },
			latestAllowedVersion: null,
		});
	});
});

describe("LicenseError", () => {
	it("is rebuilt from the error DTO", async () => {
		mockCommands({
			set_license_key: () => {
				throw {
					code: "version_not_allowed",
					message: "Too new",
					status: 403,
					latestAllowedVersion: "2.3.1",
				};
			},
		});
		const error = await sdk.setLicenseKey("KEY").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(LicenseError);
		expect(error).toBeInstanceOf(Error);
		expect(error).toMatchObject({
			name: "LicenseError",
			code: "version_not_allowed",
			message: "Too new",
			status: 403,
			latestAllowedVersion: "2.3.1",
			isLocking: true,
		});
	});

	it("leaves status and latestAllowedVersion undefined when absent", async () => {
		mockCommands({
			set_license_key: () => {
				throw { code: "network_error", message: "offline" };
			},
		});
		const error = (await sdk
			.setLicenseKey("KEY")
			.catch((e: unknown) => e)) as LicenseError;
		expect(error.code).toBe("network_error");
		expect(error.status).toBeUndefined();
		expect(error.latestAllowedVersion).toBeUndefined();
		expect(error.isLocking).toBe(false);
	});

	it("rethrows other errors unchanged", async () => {
		mockCommands({
			set_license_key: () => {
				throw "licensemanager.set_license_key not allowed";
			},
		});
		await expect(sdk.setLicenseKey("KEY")).rejects.toBe(
			"licensemanager.set_license_key not allowed",
		);

		mockCommands({
			set_license_key: () => {
				throw { code: "teapot", message: "?" };
			},
		});
		const error = await sdk.setLicenseKey("KEY").catch((e: unknown) => e);
		expect(error).not.toBeInstanceOf(LicenseError);
	});

	it.each([
		["not_found", true],
		["license_expired", true],
		["version_not_allowed", true],
		["machine_limit_reached", true],
		["plan_limit_exceeded", false],
		["validation_error", false],
		["internal_error", false],
		["network_error", false],
		["invalid_response", false],
	] as const)("%s isLocking: %s", (code, locking) => {
		expect(new LicenseError(code, "x").isLocking).toBe(locking);
	});
});

describe("events", () => {
	const activeDto = {
		state: "ACTIVE",
		offline: { mode: "offline", validUntil: 2000, remainingMs: 1 },
	};

	it("onStateChange passes the state and the snapshot", async () => {
		mockCommands({});
		const listener = vi.fn();
		const unlisten = await sdk.onStateChange(listener);
		await emit(sdk.STATE_CHANGED_EVENT, activeDto);
		expect(listener).toHaveBeenCalledWith("ACTIVE", {
			state: "ACTIVE",
			offline: { mode: "offline", validUntil: new Date(2000), remainingMs: 1 },
			latestAllowedVersion: undefined,
		});

		unlisten();
		await emit(sdk.STATE_CHANGED_EVENT, activeDto);
		expect(listener).toHaveBeenCalledTimes(1);
	});

	it("watchLicense subscribes before fetching the snapshot", async () => {
		const order: string[] = [];
		const calls = mockCommands({
			get_license: () => {
				order.push("get_license");
				return { state: "MISSING_KEY", offline: { mode: "online" } };
			},
		});
		const listener = vi.fn();
		const unlisten = await sdk.watchLicense(listener);
		const commands = calls.map((c) => c.cmd);
		expect(commands.indexOf("plugin:event|listen")).toBeLessThan(
			commands.indexOf("plugin:licensemanager|get_license"),
		);
		expect(listener).toHaveBeenCalledWith({
			state: "MISSING_KEY",
			offline: { mode: "online" },
			latestAllowedVersion: undefined,
		});

		await emit(sdk.STATE_CHANGED_EVENT, activeDto);
		expect(listener).toHaveBeenLastCalledWith(
			expect.objectContaining({ state: "ACTIVE" }),
		);
		expect(listener).toHaveBeenCalledTimes(2);
		unlisten();
	});

	it("watchLicense skips the fetched snapshot when an event came first", async () => {
		mockCommands({
			get_license: async () => {
				await emit(sdk.STATE_CHANGED_EVENT, activeDto);
				return { state: "LOADING", offline: { mode: "online" } };
			},
		});
		const listener = vi.fn();
		const unlisten = await sdk.watchLicense(listener);
		expect(listener).toHaveBeenCalledTimes(1);
		expect(listener).toHaveBeenCalledWith(
			expect.objectContaining({ state: "ACTIVE" }),
		);
		unlisten();
	});

	it("watchLicense unsubscribes when the snapshot can't be fetched", async () => {
		mockCommands({
			get_license: () => {
				throw "not allowed";
			},
		});
		const listener = vi.fn();
		await expect(sdk.watchLicense(listener)).rejects.toBe("not allowed");
		await emit(sdk.STATE_CHANGED_EVENT, activeDto);
		expect(listener).not.toHaveBeenCalled();
	});
});
