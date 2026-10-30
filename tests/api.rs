//! `core/api.rs` against a real HTTP server, with real time and reqwest.

use std::time::{Duration, Instant};

use serde_json::json;
use tauri_plugin_licensemanager::testing::{
    post_validate_key, reqwest_transport, ValidateKeyRequest,
};
use tauri_plugin_licensemanager::{LatestAllowedVersion, LicenseErrorCode};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn request() -> ValidateKeyRequest {
    ValidateKeyRequest {
        key: "KEY".into(),
        fingerprint: "fp".into(),
        version: "1.2.3".into(),
        name: "Jane's MacBook".into(),
        platform: "macOS".into(),
    }
}

async fn call(
    server: &MockServer,
    product_id: &str,
    timeout: Duration,
) -> Result<(String, u16), tauri_plugin_licensemanager::LicenseError> {
    post_validate_key(
        &*reqwest_transport(),
        &server.uri(),
        product_id,
        &request(),
        timeout,
    )
    .await
}

#[tokio::test]
async fn posts_json_and_returns_the_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/products/a%2Fb/validate-key"))
        .and(header("content-type", "application/json"))
        .and(body_json(json!({
            "key": "KEY", "fingerprint": "fp", "version": "1.2.3",
            "name": "Jane's MacBook", "platform": "macOS",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "license": "tok" })))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        call(&server, "a/b", Duration::from_secs(10)).await,
        Ok(("tok".into(), 201))
    );
}

#[tokio::test]
async fn parses_error_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": { "code": "version_not_allowed", "message": "Too new", "latestAllowedVersion": "1.1.0" }
        })))
        .mount(&server)
        .await;
    let error = call(&server, "p", Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::VersionNotAllowed);
    assert_eq!(error.message, "Too new");
    assert_eq!(error.status, Some(403));
    assert_eq!(
        error.latest_allowed_version,
        LatestAllowedVersion::Version("1.1.0".into())
    );
    assert!(error.is_locking());
}

#[tokio::test]
async fn maps_unknown_codes_to_network_error_with_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(418).set_body_json(json!({ "error": { "code": "teapot" } })),
        )
        .mount(&server)
        .await;
    let error = call(&server, "p", Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert_eq!(error.status, Some(418));
    assert_eq!(error.message, "License server answered 418");
}

#[tokio::test]
async fn treats_a_non_json_body_as_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>Bad gateway</html>"))
        .mount(&server)
        .await;
    let error = call(&server, "p", Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert_eq!(error.status, Some(502));
}

#[tokio::test]
async fn rejects_a_2xx_without_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "license": 42 })))
        .mount(&server)
        .await;
    let error = call(&server, "p", Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::InvalidResponse);
    assert_eq!(error.status, Some(200));
}

#[tokio::test]
async fn times_out_as_network_error_without_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let started = Instant::now();
    let error = call(&server, "p", Duration::from_millis(200))
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert_eq!(error.status, None);

    // A zero budget fails at once.
    let error = call(&server, "p", Duration::ZERO).await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
}

#[tokio::test]
async fn reports_connection_errors_as_network_error() {
    // A port nothing listens on.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let error = post_validate_key(
        &*reqwest_transport(),
        &uri,
        "p",
        &request(),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert_eq!(error.status, None);
    assert_eq!(error.message, "The license server could not be reached");
}

#[tokio::test]
async fn reads_the_date_header() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("date", "Thu, 01 Jan 2026 00:00:00 GMT"),
        )
        .mount(&server)
        .await;
    let date = reqwest_transport().head_date(&server.uri()).await.unwrap();
    assert_eq!(date.as_deref(), Some("Thu, 01 Jan 2026 00:00:00 GMT"));
}
