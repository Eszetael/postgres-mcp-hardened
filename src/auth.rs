use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Claims per OAuth 2.1 / OIDC: sub, exp, aud, iss, scope (space separated).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    #[serde(default)]
    pub aud: String,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub scope: String,
}

/// Authorization context produced by a successful token validation.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant: String,
    pub scopes: Vec<String>,
}

impl AuthContext {
    /// Whether the context carries a given scope (exact match).
    pub fn has_scope(&self, s: &str) -> bool {
        self.scopes.iter().any(|scope| scope == s)
    }
}

/// Validation errors are returned as plain strings.
pub fn validate_token(
    token: &str,
    pubkey_pem: &[u8],
    expected_aud: &str,
    expected_iss: &str,
) -> Result<AuthContext, String> {
    let key = DecodingKey::from_rsa_pem(pubkey_pem).map_err(|e| format!("bad key: {e}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    // jsonwebtoken validates aud/iss ONLY when the claim is present in the token. Without demanding
    // their presence, a token WITHOUT aud/iss passed despite a configured audience. They are added to
    // required_spec_claims when configured, so a missing claim means rejection.
    let mut required: Vec<String> = vec!["exp".into()];
    if !expected_aud.is_empty() {
        validation.set_audience(&[expected_aud]);
        required.push("aud".into());
    } else {
        validation.validate_aud = false;
    }
    if !expected_iss.is_empty() {
        validation.set_issuer(&[expected_iss]);
        required.push("iss".into());
    }
    validation.set_required_spec_claims(&required);
    // exp is validated by default (validate_exp = true)

    let token_data =
        decode::<Claims>(token, &key, &validation).map_err(|e| format!("token invalid: {e}"))?;

    let claims = token_data.claims;
    Ok(AuthContext {
        tenant: claims.sub,
        scopes: claims.scope.split_whitespace().map(String::from).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    use once_cell::sync::Lazy;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    // Ephemeral RS256 pair generated at RUNTIME — NO private key lives in the source
    // (a hard requirement for a security product going public). Generated once per test process.
    static KEYS: Lazy<(String, String)> = Lazy::new(|| {
        let mut rng = rand::thread_rng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).expect("gen rsa");
        let pk = RsaPublicKey::from(&sk);
        let priv_pem = sk
            .to_pkcs8_pem(LineEnding::LF)
            .expect("priv pem")
            .as_str()
            .to_string();
        let pub_pem = pk.to_public_key_pem(LineEnding::LF).expect("pub pem");
        (priv_pem, pub_pem)
    });
    fn priv_pem() -> Vec<u8> {
        KEYS.0.as_bytes().to_vec()
    }
    fn pub_pem() -> Vec<u8> {
        KEYS.1.as_bytes().to_vec()
    }

    fn now() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
    }

    /// Mints an RS256 JWT for tests.
    fn mint(scope: &str, aud: &str, iss: &str, exp_offset: i64) -> String {
        let exp = (now() as i64 + exp_offset) as usize;
        let claims = json!({
            "sub": "tenant-42",
            "exp": exp,
            "aud": aud,
            "iss": iss,
            "scope": scope,
        });
        let key = EncodingKey::from_rsa_pem(&priv_pem()).expect("test priv key load");
        encode(&Header::new(Algorithm::RS256), &claims, &key).expect("encode token")
    }

    #[test]
    fn test_valid_token() {
        let token = mint("mcp:read mcp:query", "mcp.pg", "https://idp", 3600);
        let ctx = validate_token(&token, &pub_pem(), "mcp.pg", "https://idp").expect("valid token");
        assert_eq!(ctx.tenant, "tenant-42");
        assert!(ctx.has_scope("mcp:query"));
        assert!(ctx.has_scope("mcp:read"));
    }

    #[test]
    fn test_expired_token() {
        let token = mint("mcp:read", "mcp.pg", "https://idp", -120); // expired 2 min ago (beyond the 60s leeway)
        let err = validate_token(&token, &pub_pem(), "mcp.pg", "https://idp").unwrap_err();
        assert!(err.contains("token invalid"));
    }

    #[test]
    fn test_wrong_audience() {
        let token = mint("mcp:read", "mcp.pg", "https://idp", 3600);
        let err = validate_token(&token, &pub_pem(), "other.aud", "https://idp").unwrap_err();
        assert!(err.contains("token invalid"));
    }
}
