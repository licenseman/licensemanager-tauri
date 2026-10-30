//! HTTP access, behind a trait so tests can script the server.

use futures::future::BoxFuture;
use futures::FutureExt;

/// An HTTP answer: status and raw body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Raw body; empty when it couldn't be read.
    pub body: Vec<u8>,
}

/// The request never got an HTTP answer (DNS, connection, TLS…).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);

/// The two HTTP calls the SDK makes. Timeouts are applied by the callers.
pub trait Transport: Send + Sync + 'static {
    /// `POST url` with a JSON `body`.
    fn post_validate(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> BoxFuture<'static, Result<HttpResponse, TransportError>>;

    /// `HEAD url`, without cache, returning its `Date` header.
    fn head_date(&self, url: &str) -> BoxFuture<'static, Result<Option<String>, TransportError>>;
}

/// [`Transport`] over `reqwest` with rustls.
pub(crate) struct ReqwestTransport {
    client: Option<reqwest::Client>,
}

impl ReqwestTransport {
    pub(crate) fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!(
                "tauri-plugin-licensemanager/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .ok();
        Self { client }
    }

    fn client(&self) -> Result<reqwest::Client, TransportError> {
        self.client
            .clone()
            .ok_or_else(|| TransportError("HTTP client unavailable".into()))
    }
}

impl Transport for ReqwestTransport {
    fn post_validate(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> BoxFuture<'static, Result<HttpResponse, TransportError>> {
        let client = self.client();
        let url = url.to_owned();
        async move {
            let res = client?
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            let status = res.status().as_u16();
            // An unreadable body is treated like an empty one.
            let body = res.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            Ok(HttpResponse { status, body })
        }
        .boxed()
    }

    fn head_date(&self, url: &str) -> BoxFuture<'static, Result<Option<String>, TransportError>> {
        let client = self.client();
        let url = url.to_owned();
        async move {
            let res = client?
                .head(url)
                .header(reqwest::header::CACHE_CONTROL, "no-store")
                .send()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(res
                .headers()
                .get(reqwest::header::DATE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned))
        }
        .boxed()
    }
}
