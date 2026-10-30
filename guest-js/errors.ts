/**
 * Error codes returned by the validate-key endpoint, plus SDK-side codes for
 * failures that never reached a definitive server answer.
 */
export type LicenseErrorCode =
	| "not_found"
	| "license_expired"
	| "version_not_allowed"
	| "machine_limit_reached"
	| "plan_limit_exceeded"
	| "validation_error"
	| "internal_error"
	/** Server unreachable, timed out, or answered with an unknown error. */
	| "network_error"
	/** Server answered 2xx but its token was missing or failed verification. */
	| "invalid_response";

const LICENSE_ERROR_CODES: ReadonlySet<string> = new Set<LicenseErrorCode>([
	"not_found",
	"license_expired",
	"version_not_allowed",
	"machine_limit_reached",
	"plan_limit_exceeded",
	"validation_error",
	"internal_error",
	"network_error",
	"invalid_response",
]);

/**
 * Codes that say something about the customer's license, and therefore lock
 * the app. Every other failure is treated like the server being unreachable.
 */
const LOCKING_CODES: ReadonlySet<string> = new Set<LicenseErrorCode>([
	"not_found",
	"license_expired",
	"version_not_allowed",
	"machine_limit_reached",
]);

/** Serialized `LicenseError`, as sent by the plugin's commands. */
export interface LicenseErrorDto {
	code: LicenseErrorCode;
	message: string;
	status?: number;
	latestAllowedVersion?: string | null;
}

/** Whether `value` is a serialized `LicenseError`. */
export function isLicenseErrorDto(value: unknown): value is LicenseErrorDto {
	if (typeof value !== "object" || value === null) return false;
	const { code, message } = value as Record<string, unknown>;
	return (
		typeof code === "string" &&
		LICENSE_ERROR_CODES.has(code) &&
		typeof message === "string"
	);
}

/** A failed license validation. Branch on {@link code}, never on `message`. */
export class LicenseError extends Error {
	readonly code: LicenseErrorCode;
	/** HTTP status, when the server answered. */
	readonly status: number | undefined;
	/**
	 * For `version_not_allowed`: latest version the license allows, or null
	 * when it allows none.
	 */
	readonly latestAllowedVersion: string | null | undefined;

	constructor(
		code: LicenseErrorCode,
		message: string,
		options: {
			status?: number | undefined;
			latestAllowedVersion?: string | null | undefined;
			cause?: unknown;
		} = {},
	) {
		super(message, { cause: options.cause });
		this.name = "LicenseError";
		this.code = code;
		this.status = options.status;
		this.latestAllowedVersion = options.latestAllowedVersion;
	}

	/** Rebuild an error sent by the plugin. */
	static fromDto(dto: LicenseErrorDto): LicenseError {
		return new LicenseError(dto.code, dto.message, {
			status: dto.status,
			latestAllowedVersion: dto.latestAllowedVersion,
			cause: dto,
		});
	}

	/** True when the license itself was refused (the app should lock). */
	get isLocking(): boolean {
		return LOCKING_CODES.has(this.code);
	}
}
