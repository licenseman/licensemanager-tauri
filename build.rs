const COMMANDS: &[&str] = &[
    "get_state",
    "ready",
    "get_license",
    "set_license_key",
    "refresh",
    "get_offline_state",
    "get_latest_allowed_version",
    "get_portal_url",
    "is_clock_tampered",
    "get_license_key_hint",
    "get_license_key",
    "get_fingerprint",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
