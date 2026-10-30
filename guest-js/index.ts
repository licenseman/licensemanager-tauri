import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { isLicenseErrorDto, LicenseError } from "./errors.js";

export type { UnlistenFn } from "@tauri-apps/api/event";
export type { LicenseErrorCode, LicenseErrorDto } from "./errors.js";
export { LicenseError } from "./errors.js";

export const SDK_NAME = "@licenseman/tauri";

/** Event emitted by the plugin on every state change. */
export const STATE_CHANGED_EVENT = "licensemanager://state-changed";

export type LicenseState =
	/** Startup validation in progress. */
	| "LOADING"
	/** No license key stored yet: ask the user for one. */
	| "MISSING_KEY"
	/** Valid license, verified online or with the stored token. */
	| "ACTIVE"
	/** The key does not exist for this product. */
	| "INVALID_KEY"
	/** The license expiration date has passed. */
	| "EXPIRED"
	/** The license doesn't include this app version. See {@link getLatestAllowedVersion}. */
	| "VERSION_NOT_ALLOWED"
	/** The license is active on its maximum number of machines. */
	| "MACHINE_LIMIT_REACHED"
	/** Server unreachable and no valid stored token. */
	| "OFFLINE_EXPIRED"
	/** Server unreachable and the system clock was rolled back. */
	| "CLOCK_TAMPERED";

export type OfflineState =
	| { mode: "online" }
	| {
			mode: "offline";
			/** Expiry of the stored token, or null when there is no valid token. */
			validUntil: Date | null;
			/** Time left before {@link validUntil}; 0 without a valid token. */
			remainingMs: number;
	  };

/** Everything needed to render the license, in one object. */
export interface LicenseSnapshot {
	state: LicenseState;
	offline: OfflineState;
	/**
	 * In state `VERSION_NOT_ALLOWED`: the latest version the license allows, or
	 * null when it allows none. Undefined otherwise.
	 */
	latestAllowedVersion: string | null | undefined;
}

type OfflineStateDto =
	| { mode: "online" }
	| { mode: "offline"; validUntil: number | null; remainingMs: number };

interface SnapshotDto {
	state: LicenseState;
	offline: OfflineStateDto;
	latestAllowedVersion?: string | null;
}

function command<T>(name: string, args?: Record<string, unknown>): Promise<T> {
	return invoke<T>(`plugin:licensemanager|${name}`, args);
}

function toOfflineState(dto: OfflineStateDto): OfflineState {
	if (dto.mode === "online") return { mode: "online" };
	return {
		mode: "offline",
		validUntil: dto.validUntil === null ? null : new Date(dto.validUntil),
		remainingMs: dto.remainingMs,
	};
}

function toSnapshot(dto: SnapshotDto): LicenseSnapshot {
	return {
		state: dto.state,
		offline: toOfflineState(dto.offline),
		latestAllowedVersion: dto.latestAllowedVersion,
	};
}

/** The current state. */
export function getState(): Promise<LicenseState> {
	return command("get_state");
}

/**
 * Resolves with the state once startup validation has completed, or as soon
 * as the stored token is found valid.
 */
export function ready(): Promise<LicenseState> {
	return command("ready");
}

/** State, offline state and latest allowed version in one call. */
export async function getLicense(): Promise<LicenseSnapshot> {
	return toSnapshot(await command<SnapshotDto>("get_license"));
}

/**
 * Validate a key the user typed and, on success, store it and activate. The
 * key is trimmed but its case is kept.
 *
 * @throws {LicenseError} when validation fails for any reason, including the
 *   server being unreachable. Nothing is stored and the current state is left
 *   untouched. Other failures (e.g. a missing permission) are rethrown as is.
 */
export async function setLicenseKey(key: string): Promise<LicenseState> {
	try {
		return await command<LicenseState>("set_license_key", { key });
	} catch (error) {
		throw isLicenseErrorDto(error) ? LicenseError.fromDto(error) : error;
	}
}

/**
 * Re-validate the stored key now, e.g. after the customer renewed an expired
 * license. Never fails because of the license server.
 */
export function refresh(): Promise<LicenseState> {
	return command("refresh");
}

/**
 * Whether the last validation reached the server. When offline, the app keeps
 * running on the stored token until `validUntil`.
 */
export async function getOfflineState(): Promise<OfflineState> {
	return toOfflineState(await command<OfflineStateDto>("get_offline_state"));
}

/**
 * In state `VERSION_NOT_ALLOWED`: the latest version the license allows, or
 * null when it allows none. Undefined otherwise, and when the refusal came
 * from the stored token while offline.
 */
export async function getLatestAllowedVersion(): Promise<
	string | null | undefined
> {
	const result = await command<{ latestAllowedVersion?: string | null }>(
		"get_latest_allowed_version",
	);
	return result.latestAllowedVersion;
}

/**
 * Link to the customer portal for this product. Open it with
 * `@tauri-apps/plugin-opener`: `openUrl(await getPortalUrl())`.
 */
export function getPortalUrl(): Promise<string> {
	return command("get_portal_url");
}

/** True once a backwards clock jump has been observed. */
export function isClockTampered(): Promise<boolean> {
	return command("is_clock_tampered");
}

/** Last 5 characters of the stored key, or null before one was set. */
export function getLicenseKeyHint(): Promise<string | null> {
	return command("get_license_key_hint");
}

/**
 * The stored license key, or null. Needs the
 * `licensemanager:allow-get-license-key` permission.
 */
export function getLicenseKey(): Promise<string | null> {
	return command("get_license_key");
}

/**
 * This machine's fingerprint. Needs the `licensemanager:allow-get-fingerprint`
 * permission.
 */
export function getFingerprint(): Promise<string> {
	return command("get_fingerprint");
}

/** Call `listener` on every state change. */
export function onStateChange(
	listener: (state: LicenseState, snapshot: LicenseSnapshot) => void,
): Promise<UnlistenFn> {
	return listen<SnapshotDto>(STATE_CHANGED_EVENT, (event) => {
		listener(event.payload.state, toSnapshot(event.payload));
	});
}

/**
 * Subscribes, then calls `listener` with the current snapshot and every
 * change, so a window opened after a state change never misses it.
 */
export async function watchLicense(
	listener: (snapshot: LicenseSnapshot) => void,
): Promise<UnlistenFn> {
	let changed = false;
	const unlisten = await listen<SnapshotDto>(STATE_CHANGED_EVENT, (event) => {
		changed = true;
		listener(toSnapshot(event.payload));
	});
	try {
		const snapshot = await getLicense();
		// An event received meanwhile is at least as recent as the snapshot.
		if (!changed) listener(snapshot);
	} catch (error) {
		unlisten();
		throw error;
	}
	return unlisten;
}
