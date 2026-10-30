//! Port of `license-token.ts`.

use std::sync::Arc;

use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

use super::clock::Clock;
use super::error::ConfigError;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Never re-validate sooner than this after a validation because of
/// `min_offline_duration`.
const MIN_REFRESH_INTERVAL_MS: i64 = DAY_MS;

/// Claims of a verified license token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenPayload {
    /// Issued at, in seconds.
    pub iat: i64,
    /// Expires at, in seconds.
    pub exp: i64,
    /// Max app version the license allows (`"2"`, `"2.3"`); `None` for all.
    pub mv: Option<String>,
    /// Fingerprint of the machine the token was issued for.
    pub fp: String,
}

/// A token as received from the server, with its verified payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedToken {
    pub token: String,
    pub payload: TokenPayload,
}

/// Why a token was refused. Only used internally and in tests.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct TokenError(pub String);

/// Verifies license tokens against the product's public key.
pub(crate) struct TokenVerifier {
    key: DecodingKey,
    product_id: String,
    clock: Arc<dyn Clock>,
}

impl TokenVerifier {
    /// Parses the SPKI PEM once.
    pub(crate) fn new(
        public_key: &str,
        product_id: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ConfigError> {
        let verifying_key = VerifyingKey::from_public_key_pem(public_key.trim())
            .map_err(|e| ConfigError::InvalidPublicKey(e.to_string()))?;
        Ok(Self {
            key: DecodingKey::from_ed_der(verifying_key.as_bytes()),
            product_id: product_id.to_owned(),
            clock,
        })
    }

    /// Verify signature and claims, as documented for offline validation:
    /// EdDSA only, `aud` = product, `sub` = key, `exp`/`nbf` checked against
    /// the wall clock with no leeway (jose's semantics), then `fp` must equal
    /// `fingerprint`.
    pub(crate) fn verify(
        &self,
        token: &str,
        key: &str,
        fingerprint: &str,
    ) -> Result<TokenPayload, TokenError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        // Time and audience are checked below, against the injectable clock.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Value>(token, &self.key, &validation)
            .map_err(|e| TokenError(e.to_string()))?
            .claims;

        let now = self.clock.now_ms().div_euclid(1000);
        let exp = number_claim(&claims, "exp")?;
        let iat = number_claim(&claims, "iat")?;
        if exp <= now {
            return Err(TokenError("\"exp\" claim timestamp check failed".into()));
        }
        if let Some(nbf) = claims.get("nbf") {
            let nbf = nbf
                .as_f64()
                .ok_or_else(|| TokenError("\"nbf\" claim must be a number".into()))?;
            if nbf > now as f64 {
                return Err(TokenError("\"nbf\" claim timestamp check failed".into()));
            }
        }
        let audience_ok = match claims.get("aud") {
            Some(Value::String(aud)) => *aud == self.product_id,
            Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(&self.product_id)),
            _ => false,
        };
        if !audience_ok {
            return Err(TokenError("unexpected \"aud\" claim value".into()));
        }
        if claims.get("sub").and_then(Value::as_str) != Some(key) {
            return Err(TokenError("unexpected \"sub\" claim value".into()));
        }
        if claims.get("fp").and_then(Value::as_str) != Some(fingerprint) {
            return Err(TokenError("Token of another machine".into()));
        }
        let mv = match claims.get("mv") {
            Some(Value::String(mv)) => Some(mv.clone()),
            // JS coerces a number to its string; other values parse as nothing.
            Some(Value::Number(mv)) => Some(mv.to_string()),
            _ => None,
        };
        Ok(TokenPayload {
            iat,
            exp,
            mv,
            fp: fingerprint.to_owned(),
        })
    }
}

fn number_claim(claims: &Value, name: &str) -> Result<i64, TokenError> {
    claims
        .get(name)
        .and_then(Value::as_f64)
        .map(|v| v.floor() as i64)
        .ok_or_else(|| TokenError("Token without iat or exp".into()))
}

/// When to re-validate a token, in ms since the epoch: at 2/3 of its
/// lifetime, or earlier to keep `min_offline_ms` of validity, though
/// `min_offline_ms` never pulls it within 1 day of issue.
pub(crate) fn compute_refresh_at(payload: &TokenPayload, min_offline_ms: i64) -> i64 {
    let issued_at = payload.iat * 1000;
    let expires_at = payload.exp * 1000;
    let two_thirds = issued_at + (expires_at - issued_at) * 2 / 3;
    let keep_offline = (expires_at - min_offline_ms).max(issued_at + MIN_REFRESH_INTERVAL_MS);
    two_thirds.min(keep_offline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{FakeClock, Keys, PRODUCT_ID, START_MS};

    const HOUR: i64 = 60 * 60 * 1000;
    const DAY: i64 = 24 * HOUR;
    const WEEK: i64 = 7 * DAY;

    fn at(lifetime_ms: i64, min_offline_ms: i64) -> i64 {
        let payload = TokenPayload {
            iat: 0,
            exp: lifetime_ms / 1000,
            mv: None,
            fp: String::new(),
        };
        compute_refresh_at(&payload, min_offline_ms)
    }

    #[test]
    fn refreshes_at_2_3_of_the_lifetime() {
        assert_eq!(at(3 * WEEK, 0), 2 * WEEK);
    }

    #[test]
    fn keeps_min_offline_duration_of_validity() {
        assert_eq!(at(3 * WEEK, 3 * WEEK / 2), 3 * WEEK / 2);
    }

    #[test]
    fn ignores_min_offline_duration_below_the_2_3_margin() {
        assert_eq!(at(3 * WEEK, 2 * DAY), 2 * WEEK);
    }

    #[test]
    fn never_refreshes_within_a_day_because_of_min_offline_duration() {
        assert_eq!(at(3 * WEEK, 10 * WEEK), DAY);
    }

    #[test]
    fn still_refreshes_short_tokens_at_2_3() {
        assert_eq!(at(HOUR, 10 * WEEK), 2 * HOUR / 3);
    }

    #[tokio::test(start_paused = true)]
    async fn verifies_claims() {
        let keys = Keys::get();
        let clock = Arc::new(FakeClock::new());
        let verifier = TokenVerifier::new(&keys.public_pem, PRODUCT_ID, clock.clone()).unwrap();
        let token = keys.sign_with(&serde_json::json!({
            "aud": [PRODUCT_ID, "other"], "sub": "KEY", "fp": "fp",
            "iat": START_MS / 1000, "exp": START_MS / 1000 + 60, "mv": 2,
        }));
        let payload = verifier.verify(&token, "KEY", "fp").unwrap();
        assert_eq!(payload.mv.as_deref(), Some("2"));
        assert_eq!(payload.iat, START_MS / 1000);

        // Not yet valid.
        let token = keys.sign_with(&serde_json::json!({
            "aud": PRODUCT_ID, "sub": "KEY", "fp": "fp",
            "iat": START_MS / 1000, "exp": START_MS / 1000 + 60, "nbf": START_MS / 1000 + 10,
        }));
        assert!(verifier.verify(&token, "KEY", "fp").is_err());
        // Non-numeric nbf.
        let token = keys.sign_with(&serde_json::json!({
            "aud": PRODUCT_ID, "sub": "KEY", "fp": "fp",
            "iat": START_MS / 1000, "exp": START_MS / 1000 + 60, "nbf": "soon",
        }));
        assert!(verifier.verify(&token, "KEY", "fp").is_err());
        // Missing iat.
        let token = keys.sign_with(&serde_json::json!({
            "aud": PRODUCT_ID, "sub": "KEY", "fp": "fp", "exp": START_MS / 1000 + 60,
        }));
        assert_eq!(
            verifier.verify(&token, "KEY", "fp").unwrap_err().0,
            "Token without iat or exp"
        );
        // Missing exp.
        let token = keys.sign_with(&serde_json::json!({
            "aud": PRODUCT_ID, "sub": "KEY", "fp": "fp", "iat": START_MS / 1000,
        }));
        assert!(verifier.verify(&token, "KEY", "fp").is_err());
        // Expires exactly now (jose: exp <= now is expired).
        let token = keys.sign_with(&serde_json::json!({
            "aud": PRODUCT_ID, "sub": "KEY", "fp": "fp",
            "iat": START_MS / 1000 - 60, "exp": START_MS / 1000,
        }));
        assert!(verifier.verify(&token, "KEY", "fp").is_err());
        // Missing aud.
        let token = keys.sign_with(&serde_json::json!({
            "sub": "KEY", "fp": "fp", "iat": START_MS / 1000, "exp": START_MS / 1000 + 60,
        }));
        assert!(verifier.verify(&token, "KEY", "fp").is_err());
    }

    #[test]
    fn rejects_an_invalid_public_key() {
        let clock = Arc::new(crate::core::clock::SystemClock);
        assert!(matches!(
            TokenVerifier::new("pub", PRODUCT_ID, clock.clone()),
            Err(ConfigError::InvalidPublicKey(_))
        ));
        // An RSA-sized blob is not an Ed25519 key either.
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----\n";
        assert!(TokenVerifier::new(pem, PRODUCT_ID, clock).is_err());
    }
}
