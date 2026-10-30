//! Port of `version.ts`.

/// Leading `major[.minor]` numbers of a version, ignoring patch and suffixes:
/// the regex `^\s*v?(\d+)(?:\.(\d+))?`.
fn parse_major_minor(version: &str) -> Option<(f64, Option<f64>)> {
    let rest = version.trim_start();
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    let (major, rest) = leading_digits(rest)?;
    let minor = rest
        .strip_prefix('.')
        .and_then(leading_digits)
        .map(|(m, _)| m);
    Some((major, minor))
}

/// Parses leading ASCII digits like JS `Number("0042")`.
fn leading_digits(s: &str) -> Option<(f64, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some((s[..end].parse().ok()?, &s[end..]))
}

/// Whether a license token's `mv` claim allows `version`. `mv` is a major
/// (`"2"`: all 2.x.x and older), a major.minor (`"2.3"`: all 2.3.x and older),
/// or `None` (every version). A value that can't be parsed allows the version:
/// the server stays the authoritative check.
pub(crate) fn is_version_allowed(version: &str, max_version: Option<&str>) -> bool {
    let Some(max_version) = max_version else {
        return true;
    };
    let (Some((max_major, max_minor)), Some((major, minor))) =
        (parse_major_minor(max_version), parse_major_minor(version))
    else {
        return true;
    };
    let minor = minor.unwrap_or(0.0);
    if major != max_major {
        return major < max_major;
    }
    max_minor.is_none_or(|max_minor| minor <= max_minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_version_allowed_table() {
        let cases: &[(&str, Option<&str>, bool)] = &[
            ("2.3.1", None, true),
            ("2.9.9", Some("2"), true),
            ("1.0.0", Some("2"), true),
            ("3.0.0", Some("2"), false),
            ("2.3.9", Some("2.3"), true),
            ("2.2.0", Some("2.3"), true),
            ("1.9.0", Some("2.3"), true),
            ("2.4.0", Some("2.3"), false),
            ("3.0.0", Some("2.3"), false),
            ("2", Some("2.3"), true),
            ("v2.3.1", Some("2.3"), true),
            ("2.4.0-beta.1", Some("2.3"), false),
            ("2.3.1", Some("garbage"), true),
            ("garbage", Some("2.3"), true),
        ];
        for &(version, mv, expected) in cases {
            assert_eq!(
                is_version_allowed(version, mv),
                expected,
                "{version} with mv {mv:?}"
            );
        }
    }

    #[test]
    fn accepts_leading_whitespace_and_zeros() {
        assert!(is_version_allowed("  02.3", Some("2.3")));
        assert!(!is_version_allowed(" v3", Some("2")));
        assert!(is_version_allowed("2.x", Some("2.0")));
    }
}
