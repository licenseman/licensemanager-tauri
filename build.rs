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

/// Common Controls v6, which Tauri links against on Windows. Without it in the
/// manifest, the test binaries exit with STATUS_ENTRYPOINT_NOT_FOUND.
const WINDOWS_TEST_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
</assembly>
"#;

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();

    // Link arguments only apply to this package's own linked targets (its test
    // binaries), never to the apps depending on it.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
        let manifest = out_dir.join("windows-test.manifest");
        std::fs::write(&manifest, WINDOWS_TEST_MANIFEST).expect("write the test manifest");
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
}
