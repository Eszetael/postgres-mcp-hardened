//! Who is allowed to call what.
//!
//! Two mechanisms answer the same question: a shared bearer token for deployments without an
//! identity provider, and OAuth 2.1 where there is one. They are not alternatives at runtime — when
//! OAuth is configured the shared token is ignored, because accepting either would let anyone
//! holding the secret act with full scope while the audit recorded no identity at all.

use crate::*;

pub struct AuthConfig {
    pub pubkey: Vec<u8>,
    pub aud: String,
    pub iss: String,
}

/// Reads `JWT_PUBKEY_PEM` as either the PEM text itself or a path to a `.pem` file.
///
/// Both spellings occur in the wild — a Kubernetes secret mounts a file, a `.env` inlines the text —
/// and `MCP_SSLROOTCERT` already accepts a path, so accepting only one here was a trap that cost a
/// startup failure with a message that looked like a corrupt key.
pub(crate) fn jwt_pubkey_pem() -> Option<Vec<u8>> {
    let raw = std::env::var("JWT_PUBKEY_PEM").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("-----BEGIN") {
        return Some(raw.as_bytes().to_vec());
    }
    std::fs::read(raw).ok()
}

pub(crate) static AUTH_CONFIG: Lazy<Option<AuthConfig>> = Lazy::new(|| {
    let pem = jwt_pubkey_pem()?;
    Some(AuthConfig {
        pubkey: pem,
        aud: std::env::var("JWT_AUD").unwrap_or_default(),
        iss: std::env::var("JWT_ISS").unwrap_or_default(),
    })
});

/// The token out of an `Authorization: Bearer …` header, per RFC 7235 and RFC 6750.
///
/// Written out because `strip_prefix("Bearer ")` is not what those documents say, and the difference
/// is visible from outside. RFC 7235 §2.1: "The scheme is case-insensitive." RFC 6750's grammar is
/// `credentials = "Bearer" 1*SP b64token`, and a quoted string in ABNF is case-insensitive too, so
/// `bearer`, `BEARER` and `BeArEr` are all correct spellings, as is more than one space before the
/// token. Verified 2026-08-18: this server answered 200 to `Bearer` and 401 to `bearer`.
///
/// It fails closed, so it was never a way in — it is a way to be told "authentication failed" while
/// holding a valid token and a correctly formed request, which is the kind of thing somebody
/// diagnoses for twenty minutes and then goes to use something else.
///
/// The token itself is returned with leading spaces removed and nothing else touched. Trailing
/// whitespace is not this function's business: RFC 7230 §3.2.4 has the HTTP layer strip the optional
/// whitespace around a field value before anyone sees it, so `Bearer tok ` and `Bearer tok` arrive
/// here identical. Verified over the wire, because the alternative was to assert it in a comment.
pub(crate) fn bearer_token(value: &str) -> Option<&str> {
    let rest = value.strip_prefix(|c: char| c.eq_ignore_ascii_case(&'b'))?;
    let (scheme_tail, after) = rest.split_at(rest.len().min(5));
    if !scheme_tail.eq_ignore_ascii_case("earer") {
        return None;
    }
    // `1*SP`: at least one space, and more are allowed.
    let trimmed = after.strip_prefix(' ')?;
    Some(trimmed.trim_start_matches(' '))
}

/// Compares two secrets without revealing the length of the expected one.
///
/// The previous version short-circuited on `len() != len()`, which answers "how long is the token"
/// to anyone who can time it, and then compared only over that length. Hashing both sides first makes
/// every comparison the same fixed width regardless of what was supplied.
pub(crate) fn secret_eq(given: &str, expected: &str) -> bool {
    let key = SECRET_CMP_KEY.clone();
    let a = hmac_sha256_hex(key.clone(), given.as_bytes());
    let b = hmac_sha256_hex(key, expected.as_bytes());
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
        && a.len() == b.len()
}

/// A per-process key, so the digests compared above cannot be precomputed off-line.
static SECRET_CMP_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut k = Vec::with_capacity(32);
    k.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    k.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    k
});

/// The scope a tool call needs. Running SQL is a different privilege from reading the schema, and
/// `security_posture` deliberately sits with the read tools: an operator investigating a deployment
/// should not need the scope that lets them query it.
/// Which scope a tool needs. Every tool is named; nothing falls through to a default.
///
/// A fallback of `_ => "mcp:read"` is comfortable right up to the first tool that is more than a
/// read: it would inherit the mildest right in the system without anyone deciding that, and nothing
/// would say so. The fallback is therefore the STRONGEST scope — a tool nobody classified is
/// reachable only by an admin — and `every_tool_has_a_scope_decision` fails the build until someone
/// classifies it.
pub(crate) fn required_scope(tool: &str) -> &'static str {
    match tool {
        // Runs caller-supplied SQL.
        // Takes caller SQL and plans it, like explain_query.
        "query" | "explain_query" | "simulate_index" => "mcp:query",
        // Metadata about the database: schemas, tables, health, index and query statistics.
        "list_tables" | "list_schemas" | "describe_table" | "database_health"
        | "analyze_indexes" | "top_queries" => "mcp:read",
        // Reports the privileges this server holds, which is reconnaissance in its own right.
        "security_posture" => "mcp:read",
        _ => "mcp:admin",
    }
}

/// `mcp:admin` stands in for any scope. Kept as its own function so the rule is one line to read and
/// one line to test, rather than a condition buried in a long authorisation path.
pub(crate) fn scope_satisfied(ctx: &auth::AuthContext, needed: &str) -> bool {
    ctx.has_scope(needed) || ctx.has_scope("mcp:admin")
}

pub(crate) fn enforce_auth(
    headers: &HeaderMap,
    req: &Value,
) -> Result<Option<String>, (u16, String, Option<String>)> {
    // A shared bearer token: the simplest possible protection for people who do not run an identity
    // provider. Both alternatives have an open request for exactly this. Checked before OAuth so a
    // deployment can use either, and compared in constant time.
    // The shared token is the mechanism for deployments WITHOUT an identity provider. When OAuth is
    // configured it is ignored, and deliberately so: accepting it as an alternative let any holder of
    // the shared secret act with full scope while the audit recorded no identity at all. A caller
    // could opt out of being identified by presenting the shared token instead of their JWT — the
    // exact opposite of what the log exists for. Preflight says so at startup when both are set.
    // The one method that stays reachable without credentials, in BOTH modes. The specification
    // tells clients to call `server/discover` as a backwards-compatibility probe before they know
    // anything about the server — including whether it wants a token. It answers what we are and
    // which revisions we speak, and nothing about the database. What it must NOT answer to an
    // anonymous caller is the security posture; `handle_server_discover` decides that separately.
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method == "server/discover" {
        return Ok(None);
    }

    if AUTH_CONFIG.is_none() {
        if let Some(expected) = std::env::var("MCP_BEARER_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
        {
            let given = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(bearer_token)
                .unwrap_or("");
            if !secret_eq(given, &expected) {
                return Err((401, "invalid or missing bearer token".into(), None));
            }
            // An identity, not a dash. A shared token names no person, but it does name a
            // credential — and when one is rotated or leaks, the log has to be able to say which
            // requests used it. The fingerprint never reveals the token itself.
            return Ok(Some(format!(
                "bearer:{}",
                &hmac_sha256_hex(b"mcp-bearer-fingerprint".to_vec(), expected.as_bytes())[..8]
            )));
        }
    }

    let cfg = match &*AUTH_CONFIG {
        Some(c) => c,
        None => return Ok(None),
    };

    // One policy, both mechanisms. Exempting methods here and not in the shared-token path would
    // leave the same door shut with a token and open with OAuth, and an operator moving between them
    // would have no way of seeing that the tool inventory had just become anonymous. Whether a given
    // method is worth protecting is arguable; a policy that depends on which mechanism you picked
    // is not.

    // Fail-closed: auth enabled (a pubkey is set) but JWT_AUD/JWT_ISS empty means a broken config.
    // Without this, validate_token skipped the audience check and accepted ANY token signed with the key.
    //. Wymuszamy skonfigurowany audience+issuer zamiast cichego fail-open.
    if cfg.aud.is_empty() || cfg.iss.is_empty() {
        return Err((
            500,
            "server auth misconfigured: JWT_AUD and JWT_ISS are required when auth is enabled"
                .into(),
            None,
        ));
    }

    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token);

    let token = match token {
        Some(t) => t,
        None => return Err((401, "missing bearer token".into(), None)),
    };

    let ctx = auth::validate_token(token, &cfg.pubkey, &cfg.aud, &cfg.iss)
        .map_err(|e| (401u16, e, None))?;

    // Scope was checked for `tools/call` only. `resources/read` returns table and column names,
    // which the threat model calls reconnaissance in as many words — and a token deliberately issued
    // with no scope at all could read every schema in the database. Both are data; both need a
    // scope. Methods that reveal nothing about the database (initialize, tools/list, ping) need a
    // valid token, which they now have, but no particular right.
    let scoped = match method {
        "tools/call" => Some(required_scope(
            req.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )),
        "resources/read" | "resources/list" | "resources/templates/list" => Some("mcp:read"),
        _ => None,
    };
    if let Some(needed) = scoped {
        if !scope_satisfied(&ctx, needed) {
            // The identity IS known (the token is valid, only the scope is missing) — it must reach the audit,
            // because this is the insider/escalation case, exactly what the log exists to catch.
            return Err((
                403,
                format!("insufficient scope: {} required", needed),
                Some(ctx.tenant.clone()),
            ));
        }
    }

    Ok(Some(ctx.tenant))
}

#[cfg(test)]
mod bearer_tests {
    use super::bearer_token;

    /// RFC 7235 §2.1 makes the scheme case-insensitive and RFC 6750 spells it with a quoted string,
    /// which ABNF also reads case-insensitively. Before 0.1.7 this server answered 200 to `Bearer`
    /// and 401 to `bearer` — fail-closed, so never a way in, but a way to be told "authentication
    /// failed" while holding a valid token and a correctly formed request.
    #[test]
    fn the_scheme_is_case_insensitive() {
        for h in [
            "Bearer tok",
            "bearer tok",
            "BEARER tok",
            "BeArEr tok",
            "beaRER tok",
        ] {
            assert_eq!(bearer_token(h), Some("tok"), "{h}");
        }
    }

    /// `credentials = "Bearer" 1*SP b64token` — one space is required and more are allowed.
    #[test]
    fn one_space_is_required_and_more_are_allowed() {
        assert_eq!(bearer_token("Bearer tok"), Some("tok"));
        assert_eq!(bearer_token("Bearer    tok"), Some("tok"));
        assert_eq!(
            bearer_token("Bearer"),
            None,
            "no space at all is not a credential"
        );
        assert_eq!(
            bearer_token("Bearer "),
            Some(""),
            "a space and nothing after it is an empty token, which never matches"
        );
    }

    /// Anything that is not this scheme stays unrecognised. A near-miss must not fall through to
    /// "no token" in a way that could be read as "no authentication required" — the caller of this
    /// function treats `None` as unauthenticated, which is the safe direction.
    #[test]
    fn other_schemes_and_near_misses_are_not_bearer() {
        for h in [
            "Basic dG9r",
            "Bear tok",
            "Bearerr tok",
            "Bearertok",
            "XBearer tok",
            "",
            "tok",
        ] {
            assert_eq!(bearer_token(h), None, "{h}");
        }
    }
}
