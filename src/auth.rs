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
    // exp is validated by default (validate_exp = true).
    //
    // nbf is NOT, unless asked: a token minted for later use — the shape an identity provider issues
    // when it pre-authorises something — was accepted the moment it was created. Validated when
    // present, not required, because plenty of providers never set it.
    validation.validate_nbf = true;

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

    /// A second, unrelated key pair: "signed with a real RSA key" and "signed with OUR key" must be
    /// distinguishable, and only a different key proves that.
    fn other_priv_pem() -> Vec<u8> {
        static OTHER: Lazy<String> = Lazy::new(|| {
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, 2048)
                .expect("gen rsa")
                .to_pkcs8_pem(LineEnding::LF)
                .expect("priv pem")
                .as_str()
                .to_string()
        });
        OTHER.as_bytes().to_vec()
    }

    /// base64url without padding, for hand-assembling a token the library would never produce.
    fn base64_url(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for i in 0..(c.len() + 1) {
                out.push(A[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
        out
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

    /// Algorithm confusion, the attack this class of code exists to fail: the RSA PUBLIC key is
    /// public by definition, so an attacker signs an HS256 token using it as the shared secret. A
    /// validator that trusts the token's own `alg` header verifies it happily and hands out access.
    /// Ours pins RS256, so the header cannot choose the algorithm — but that has to be a test, not a
    /// belief, because the failure is invisible and total.
    #[test]
    fn hs256_signed_with_the_public_key_is_refused() {
        let claims = json!({"sub":"attacker","exp":now()+3600,"aud":"mcp.pg",
                            "iss":"https://idp","scope":"mcp:admin"});
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&pub_pem()),
        )
        .expect("forge");
        let err = validate_token(&forged, &pub_pem(), "mcp.pg", "https://idp")
            .expect_err("HS256 signed with the public key MUST be refused");
        assert!(err.contains("token invalid"), "{err}");
    }

    /// `alg: none` — the other half of the same family.
    #[test]
    fn an_unsigned_token_is_refused() {
        let header = base64_url(br#"{"alg":"none","typ":"JWT"}"#);
        let body = base64_url(
            format!(
                r#"{{"sub":"attacker","exp":{},"aud":"mcp.pg","iss":"https://idp","scope":"mcp:admin"}}"#,
                now() + 3600
            )
            .as_bytes(),
        );
        let unsigned = format!("{}.{}.", header, body);
        validate_token(&unsigned, &pub_pem(), "mcp.pg", "https://idp")
            .expect_err("an unsigned token MUST be refused");
    }

    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let token = mint("mcp:read", "mcp.pg", "https://attacker.example", 3600);
        let err = validate_token(&token, &pub_pem(), "mcp.pg", "https://idp")
            .expect_err("a foreign issuer MUST be refused");
        assert!(err.contains("token invalid"), "{err}");
    }

    /// A token carrying no `aud`/`iss` at all must not slip past a configured expectation: the
    /// library only checks a claim it can see, so their absence has to be a rejection in itself.
    #[test]
    fn a_token_missing_the_claims_we_require_is_refused() {
        let key = EncodingKey::from_rsa_pem(&priv_pem()).unwrap();
        let bare = encode(
            &Header::new(Algorithm::RS256),
            &json!({"sub":"x","exp":now()+3600,"scope":"mcp:read"}),
            &key,
        )
        .unwrap();
        validate_token(&bare, &pub_pem(), "mcp.pg", "https://idp")
            .expect_err("a token without aud/iss MUST be refused when both are configured");
    }

    /// Signed by a real RSA key — just not ours.
    #[test]
    fn a_token_signed_by_a_different_key_is_refused() {
        let other = other_priv_pem();
        let token = encode(
            &Header::new(Algorithm::RS256),
            &json!({"sub":"x","exp":now()+3600,"aud":"mcp.pg","iss":"https://idp","scope":"mcp:admin"}),
            &EncodingKey::from_rsa_pem(&other).unwrap(),
        )
        .unwrap();
        validate_token(&token, &pub_pem(), "mcp.pg", "https://idp")
            .expect_err("another key's signature MUST be refused");
    }

    /// A token that is not valid yet. jsonwebtoken does not check `nbf` unless told to, so this
    /// asserts the configuration rather than the library.
    #[test]
    fn a_token_not_yet_valid_is_refused() {
        let key = EncodingKey::from_rsa_pem(&priv_pem()).unwrap();
        let future = encode(
            &Header::new(Algorithm::RS256),
            &json!({"sub":"x","exp":now()+7200,"nbf":now()+3600,
                    "aud":"mcp.pg","iss":"https://idp","scope":"mcp:read"}),
            &key,
        )
        .unwrap();
        validate_token(&future, &pub_pem(), "mcp.pg", "https://idp")
            .expect_err("a token whose validity has not begun MUST be refused");
    }
}
