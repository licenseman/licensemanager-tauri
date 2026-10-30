//! Port of `fingerprint.ts`.

use std::future::Future;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::future::BoxFuture;
use futures::FutureExt;
use sha2::{Digest, Sha256};

/// User-supplied machine fingerprint source, replacing the native machine id.
/// The value is still hashed before use.
#[derive(Clone)]
pub enum MachineFingerprint {
    /// Used verbatim as the raw machine value.
    Static(String),
    /// Awaited once; its result is the raw machine value.
    Fn(Arc<dyn Fn() -> BoxFuture<'static, String> + Send + Sync>),
}

impl MachineFingerprint {
    /// From an async function.
    pub fn from_fn<F, Fut>(f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        Self::Fn(Arc::new(move || f().boxed()))
    }

    /// From a sync function.
    pub fn from_sync_fn<F>(f: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        Self::Fn(Arc::new(move || futures::future::ready(f()).boxed()))
    }
}

impl From<String> for MachineFingerprint {
    fn from(value: String) -> Self {
        Self::Static(value)
    }
}

impl From<&str> for MachineFingerprint {
    fn from(value: &str) -> Self {
        Self::Static(value.to_owned())
    }
}

impl std::fmt::Debug for MachineFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(value) => f.debug_tuple("Static").field(value).finish(),
            Self::Fn(_) => f.write_str("Fn(..)"),
        }
    }
}

/// Hash a raw machine value into a stable, opaque base64 digest.
pub(crate) fn hash_machine_value(raw: &str) -> String {
    STANDARD.encode(Sha256::digest(raw))
}

/// Resolve the machine component of the fingerprint from the user option,
/// returning its base64 sha256 digest.
pub(crate) async fn resolve_machine_fingerprint(option: Option<&MachineFingerprint>) -> String {
    let raw = match option {
        Some(MachineFingerprint::Static(value)) => value.clone(),
        Some(MachineFingerprint::Fn(f)) => f().await,
        None => read_machine_id().await,
    };
    hash_machine_value(&raw)
}

/// Read the OS-native machine GUID and normalise it to a stable lowercase
/// string. On failure it falls back to a hardware MAC address and finally the
/// hostname, so this never fails.
pub(crate) async fn read_machine_id() -> String {
    match read_native_machine_id().await {
        Some(id) => id,
        None => fallback_machine_id(),
    }
}

#[cfg(target_os = "macos")]
async fn read_native_machine_id() -> Option<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_darwin(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "windows")]
async fn read_native_machine_id() -> Option<String> {
    tokio::task::spawn_blocking(|| {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        let value: String = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Cryptography",
                KEY_READ | KEY_WOW64_64KEY,
            )
            .ok()?
            .get_value("MachineGuid")
            .ok()?;
        normalize_id(&value)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn read_native_machine_id() -> Option<String> {
    read_linux_machine_id(&["/etc/machine-id", "/var/lib/dbus/machine-id"]).await
}

/// `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice` output.
pub(crate) fn parse_darwin(output: &str) -> Option<String> {
    let (_, after) = output.split_once("IOPlatformUUID")?;
    let line = after.split('\n').next().unwrap_or_default();
    let value: String = line
        .chars()
        .filter(|c| *c != '=' && *c != '"' && !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    (!value.is_empty()).then_some(value)
}

/// Whitespace stripped and lowercased; `None` when empty. Used for the
/// Windows `MachineGuid` and Linux `machine-id` values.
pub(crate) fn normalize_id(raw: &str) -> Option<String> {
    let value: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    (!value.is_empty()).then_some(value)
}

/// First non-empty machine id among `paths`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), allow(dead_code))]
pub(crate) async fn read_linux_machine_id(paths: &[&str]) -> Option<String> {
    for path in paths {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            if let Some(value) = normalize_id(&content) {
                return Some(value);
            }
        }
    }
    None
}

/// First non-internal, non-zero MAC address, else the hostname. Never fails.
pub(crate) fn fallback_machine_id() -> String {
    match mac_address::get_mac_address() {
        Ok(Some(mac)) if mac.bytes() != [0; 6] => mac.to_string().to_lowercase(),
        _ => super::environment::hostname().to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[tokio::test]
    async fn hashes_a_verbatim_string() {
        let option = MachineFingerprint::from("my-machine");
        assert_eq!(
            resolve_machine_fingerprint(Some(&option)).await,
            hash_machine_value("my-machine")
        );
        let option = MachineFingerprint::from(String::from("my-machine"));
        assert_eq!(
            resolve_machine_fingerprint(Some(&option)).await,
            hash_machine_value("my-machine")
        );
    }

    #[tokio::test]
    async fn awaits_a_sync_function() {
        let option = MachineFingerprint::from_sync_fn(|| "sync-value".into());
        assert_eq!(
            resolve_machine_fingerprint(Some(&option)).await,
            hash_machine_value("sync-value")
        );
    }

    #[tokio::test]
    async fn awaits_an_async_function() {
        let option = MachineFingerprint::from_fn(|| async { "async-value".to_owned() });
        assert_eq!(
            resolve_machine_fingerprint(Some(&option)).await,
            hash_machine_value("async-value")
        );
        assert_eq!(format!("{option:?}"), "Fn(..)");
        assert_eq!(
            format!("{:?}", MachineFingerprint::from("x")),
            "Static(\"x\")"
        );
    }

    #[test]
    fn parses_the_macos_io_platform_uuid() {
        assert_eq!(
            parse_darwin(
                "+-o Root\n  \"IOPlatformUUID\" = \"ABCDEF12-3456-7890-ABCD-EF1234567890\"\n  \"x\" = 1\n"
            )
            .as_deref(),
            Some("abcdef12-3456-7890-abcd-ef1234567890")
        );
    }

    #[test]
    fn rejects_a_missing_or_empty_macos_uuid() {
        assert_eq!(parse_darwin("nothing here"), None);
        assert_eq!(parse_darwin("\"IOPlatformUUID\" = \"\"\n"), None);
    }

    #[test]
    fn normalizes_the_windows_machine_guid() {
        assert_eq!(
            normalize_id(" 11112222-3333-4444-5555-666677778888\r\n").as_deref(),
            Some("11112222-3333-4444-5555-666677778888")
        );
        assert_eq!(normalize_id(" \r\n"), None);
    }

    #[tokio::test]
    async fn reads_the_linux_machine_id_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "DEADBEEFdeadbeefdeadbeefdeadbeef").unwrap();
        let path = file.path().to_str().unwrap().to_owned();
        assert_eq!(
            read_linux_machine_id(&[&path]).await.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeef")
        );
    }

    #[tokio::test]
    async fn tries_the_dbus_path_when_etc_machine_id_is_empty() {
        let mut empty = tempfile::NamedTempFile::new().unwrap();
        writeln!(empty, "   ").unwrap();
        let mut dbus = tempfile::NamedTempFile::new().unwrap();
        writeln!(dbus, "cafecafecafecafecafecafecafecafe").unwrap();
        let paths = [
            empty.path().to_str().unwrap().to_owned(),
            dbus.path().to_str().unwrap().to_owned(),
        ];
        assert_eq!(
            read_linux_machine_id(&[&paths[0], &paths[1]])
                .await
                .as_deref(),
            Some("cafecafecafecafecafecafecafecafe")
        );
    }

    #[tokio::test]
    async fn returns_none_when_no_linux_machine_id_file_is_readable() {
        assert_eq!(
            read_linux_machine_id(&["/nonexistent/machine-id"]).await,
            None
        );
    }

    #[test]
    fn falls_back_to_a_mac_address_or_the_hostname() {
        let value = fallback_machine_id();
        assert!(!value.is_empty());
        assert_eq!(value, value.to_lowercase());
        // Fallback is a MAC address or hostname, never the digest form.
        assert!(!value.ends_with('='));
    }

    #[tokio::test]
    async fn reads_a_native_machine_id_without_failing() {
        let value = read_machine_id().await;
        assert!(!value.is_empty());
        assert_eq!(value, value.to_lowercase());
        // Cached-independent: the same value on every call.
        assert_eq!(read_machine_id().await, value);
    }

    #[test]
    fn golden_machine_hash() {
        assert_eq!(
            hash_machine_value("4c4c4544-0042-3510-8051-b4c04f4b4e32"),
            "WDpaNFX/NZW0yp1UEWsHi36rKjpX4d0zVnasSsrpJOA="
        );
    }

    #[test]
    fn hash_is_a_stable_base64_sha256_digest() {
        assert_eq!(
            hash_machine_value("x"),
            STANDARD.encode(Sha256::digest("x"))
        );
        assert_eq!(hash_machine_value("x").len(), 44);
    }
}
