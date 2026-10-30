import {
	getLicenseKeyHint,
	getPortalUrl,
	LicenseError,
	type LicenseSnapshot,
	type LicenseState,
	refresh,
	setLicenseKey,
	watchLicense,
} from "@licenseman/tauri";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

const LOCKED_MESSAGES: Partial<Record<LicenseState, [string, string]>> = {
	INVALID_KEY: ["Invalid key", "This license key does not exist."],
	EXPIRED: ["License expired", "Renew your license, then check again."],
	VERSION_NOT_ALLOWED: [
		"Version not included",
		"Your license doesn't include this version.",
	],
	MACHINE_LIMIT_REACHED: [
		"Too many machines",
		"Deactivate another machine from the portal, then check again.",
	],
	OFFLINE_EXPIRED: [
		"Offline for too long",
		"Connect to the internet to validate your license.",
	],
	CLOCK_TAMPERED: [
		"Clock changed",
		"Your system clock looks wrong. Fix it and connect to the internet.",
	],
};

function element<T extends HTMLElement>(id: string): T {
	const found = document.getElementById(id);
	if (!found) throw new Error(`#${id} not found`);
	return found as T;
}

let showActivation = false;

function show(view: "loading" | "activation" | "locked" | "app"): void {
	for (const id of ["loading", "activation", "locked", "app"]) {
		element(id).hidden = id !== view;
	}
}

async function render(snapshot: LicenseSnapshot): Promise<void> {
	const { state, offline, latestAllowedVersion } = snapshot;
	if (state === "LOADING") return show("loading");
	if (state === "MISSING_KEY" || showActivation) return show("activation");
	if (state === "ACTIVE") {
		element("license-info").textContent =
			`Key ending in ${await getLicenseKeyHint()}.`;
		element("offline-info").textContent =
			offline.mode === "offline" && offline.validUntil
				? `Offline: works until ${offline.validUntil.toLocaleString()}.`
				: "";
		return show("app");
	}
	const [title, message] = LOCKED_MESSAGES[state] ?? [state, ""];
	element("locked-title").textContent = title;
	element("locked-message").textContent =
		state === "VERSION_NOT_ALLOWED" && typeof latestAllowedVersion === "string"
			? `${message} Latest allowed version: ${latestAllowedVersion}.`
			: message;
	show("locked");
}

let latest: LicenseSnapshot | undefined;

await watchLicense((snapshot) => {
	latest = snapshot;
	void render(snapshot);
});

element<HTMLFormElement>("activation-form").addEventListener(
	"submit",
	async (event) => {
		event.preventDefault();
		const error = element("activation-error");
		error.textContent = "";
		try {
			await setLicenseKey(element<HTMLInputElement>("key").value);
			showActivation = false;
			if (latest) void render(latest);
		} catch (e) {
			error.textContent =
				e instanceof LicenseError ? `${e.message} (${e.code})` : String(e);
		}
	},
);

element("retry").addEventListener("click", () => void refresh());

element("change-key").addEventListener("click", () => {
	showActivation = true;
	show("activation");
});

for (const id of ["portal", "portal-app"]) {
	element(id).addEventListener(
		"click",
		async () => void openUrl(await getPortalUrl()),
	);
}

element("premium").addEventListener("click", async () => {
	const result = element("premium-result");
	try {
		result.textContent = await invoke<string>("premium_feature");
	} catch (e) {
		result.textContent = String(e);
	}
});
