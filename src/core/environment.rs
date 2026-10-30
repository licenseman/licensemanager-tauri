//! Port of `environment.ts`.

/// `"macOS"`, `"Windows"`, `"Linux"`, else [`std::env::consts::OS`].
pub(crate) fn default_platform() -> String {
    platform_name(std::env::consts::OS)
}

fn platform_name(os: &str) -> String {
    match os {
        "macos" => "macOS".into(),
        "windows" => "Windows".into(),
        "linux" => "Linux".into(),
        other => other.into(),
    }
}

/// The machine's hostname, shown in the dashboard by default.
pub(crate) fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_platforms_like_electron() {
        assert_eq!(platform_name("macos"), "macOS");
        assert_eq!(platform_name("windows"), "Windows");
        assert_eq!(platform_name("linux"), "Linux");
        assert_eq!(platform_name("freebsd"), "freebsd");
        assert!(!default_platform().is_empty());
        assert!(!hostname().is_empty());
    }
}
