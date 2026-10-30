//! Port of `license-api.ts`: the validate-key client.

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::Value;

use super::error::{LatestAllowedVersion, LicenseError, LicenseErrorCode};
use super::transport::Transport;

/// Default API origin.
pub(crate) const DEFAULT_API_BASE_URL: &str = "https://api.licensemanager.dev";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Characters `encodeURIComponent` escapes.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

/// JS `encodeURIComponent`.
pub(crate) fn encode_uri_component(value: &str) -> String {
    utf8_percent_encode(value, URI_COMPONENT).to_string()
}

/// Body of `POST /v1/products/{productId}/validate-key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidateKeyRequest {
    /// The license key.
    pub key: String,
    /// The machine fingerprint.
    pub fingerprint: String,
    /// The app version.
    pub version: String,
    /// The machine name shown in the dashboard.
    pub name: String,
    /// The platform shown in the dashboard.
    pub platform: String,
}

/// Call validate-key and return the unverified license token and the HTTP
/// status. `timeout` is capped at 10 seconds.
pub async fn post_validate_key(
    transport: &dyn Transport,
    api_base_url: &str,
    product_id: &str,
    request: &ValidateKeyRequest,
    timeout: Duration,
) -> Result<(String, u16), LicenseError> {
    let url = format!(
        "{api_base_url}/v1/products/{}/validate-key",
        encode_uri_component(product_id)
    );
    let body = serde_json::to_vec(request).unwrap_or_default();
    let unreachable = || {
        LicenseError::new(
            LicenseErrorCode::NetworkError,
            "The license server could not be reached",
        )
    };
    let res = tokio::time::timeout(
        timeout.min(REQUEST_TIMEOUT),
        transport.post_validate(&url, body),
    )
    .await
    .map_err(|_| unreachable())?
    .map_err(|_| unreachable())?;

    let json: Option<Value> = serde_json::from_slice(&res.body).ok();
    if !(200..300).contains(&res.status) {
        return Err(parse_server_error(res.status, json.as_ref()));
    }
    match json
        .as_ref()
        .and_then(|j| j.get("license"))
        .and_then(Value::as_str)
    {
        Some(token) => Ok((token.to_owned(), res.status)),
        None => Err(LicenseError::new(
            LicenseErrorCode::InvalidResponse,
            "The license server returned no token",
        )
        .with_status(res.status)),
    }
}

/// Whether a failed validate-key call may succeed if repeated: the server was
/// unreachable, overloaded or failing. Answers about the key are final.
pub(crate) fn is_transient(error: &LicenseError) -> bool {
    match error.status {
        None => error.code == LicenseErrorCode::NetworkError,
        Some(status) => status >= 500 || status == 408 || status == 429,
    }
}

/// Map an error response to a [`LicenseError`], branching on `code` only.
fn parse_server_error(status: u16, json: Option<&Value>) -> LicenseError {
    let error = json.and_then(|j| j.get("error"));
    let code = error
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("License server answered {status}"));
    let latest_allowed_version = if code == "version_not_allowed" {
        match error.and_then(|e| e.get("latestAllowedVersion")) {
            Some(Value::String(version)) => LatestAllowedVersion::Version(version.clone()),
            _ => LatestAllowedVersion::NoneAllowed,
        }
    } else {
        LatestAllowedVersion::NotApplicable
    };
    LicenseError {
        code: LicenseErrorCode::from_server_code(code).unwrap_or(LicenseErrorCode::NetworkError),
        message,
        status: Some(status),
        latest_allowed_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_encode_uri_component() {
        assert_eq!(encode_uri_component("a/b c"), "a%2Fb%20c");
        assert_eq!(encode_uri_component("x7Kp2QaZ"), "x7Kp2QaZ");
        assert_eq!(encode_uri_component("-_.!~*'()"), "-_.!~*'()");
        assert_eq!(encode_uri_component("é?&="), "%C3%A9%3F%26%3D");
    }

    #[test]
    fn transient_errors() {
        let network = LicenseError::new(LicenseErrorCode::NetworkError, "x");
        assert!(is_transient(&network));
        assert!(!is_transient(&LicenseError::new(
            LicenseErrorCode::InvalidResponse,
            "x"
        )));
        for status in [500, 503, 408, 429] {
            assert!(is_transient(&network.clone().with_status(status)));
        }
        for status in [400, 402, 403, 404, 422] {
            assert!(!is_transient(&network.clone().with_status(status)));
        }
    }

    #[test]
    fn parses_server_errors() {
        let json = serde_json::json!({ "error": { "code": "version_not_allowed", "message": "old", "latestAllowedVersion": "2.3.1" } });
        let error = parse_server_error(403, Some(&json));
        assert_eq!(error.code, LicenseErrorCode::VersionNotAllowed);
        assert_eq!(error.message, "old");
        assert_eq!(error.status, Some(403));
        assert_eq!(
            error.latest_allowed_version,
            LatestAllowedVersion::Version("2.3.1".into())
        );

        let json = serde_json::json!({ "error": { "code": "version_not_allowed", "latestAllowedVersion": 3 } });
        let error = parse_server_error(403, Some(&json));
        assert_eq!(
            error.latest_allowed_version,
            LatestAllowedVersion::NoneAllowed
        );
        assert_eq!(error.message, "License server answered 403");

        let json =
            serde_json::json!({ "error": { "code": "not_found", "latestAllowedVersion": "9" } });
        let error = parse_server_error(404, Some(&json));
        assert_eq!(error.code, LicenseErrorCode::NotFound);
        assert_eq!(
            error.latest_allowed_version,
            LatestAllowedVersion::NotApplicable
        );

        let error = parse_server_error(
            418,
            Some(&serde_json::json!({ "error": { "code": "teapot" } })),
        );
        assert_eq!(error.code, LicenseErrorCode::NetworkError);
        assert_eq!(error.status, Some(418));

        let error = parse_server_error(502, None);
        assert_eq!(error.code, LicenseErrorCode::NetworkError);
        assert_eq!(error.message, "License server answered 502");
    }
}
