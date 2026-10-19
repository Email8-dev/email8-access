// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! SASL bridge for the Access protocols (XOAUTH2/OAUTHBEARER →
//! Sentin8:Auth token → Store data API).

use uuid::Uuid;

use crate::config::AccessConfig;

/// An authenticated protocol session.
#[derive(Debug, Clone)]
pub struct AccessAuth {
    pub user_sub: String,
    pub env_id: uuid::Uuid,
    pub account_id: Uuid,
}

/// Decode a SASL XOAUTH2/OAUTHBEARER initial response → bearer token.
pub fn decode_xoauth2(initial: &str) -> Option<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(initial.as_bytes())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    for part in text.split('\x01') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("auth=") {
            return Some(rest.trim_start_matches("Bearer ").trim().to_string());
        }
    }
    None
}

/// Verify the bearer token, require mail scopes, and bind the auth sub
/// to an Email8 account id (principals lookup, RLS-scoped).
pub async fn verify(
    pool: &sqlx::PgPool,
    config: &AccessConfig,
    engine: &sentin8::shield::PolicyEngine,
    token: &str,
    action: &str,
) -> Result<AccessAuth, String> {
    let mut headers = axum::http::HeaderMap::new();
    let _ = headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| e.to_string())?,
    );
    let ctx = sentin8::auth::client::verify_bearer_token(&config.sentin8_auth_client, &headers)
        .await
        .map_err(|(_c, msg)| msg)?;
    sentin8::shell::policy::require(
        engine,
        &ctx,
        &headers,
        sentin8::shield::EvalTarget::new(action),
    )
    .await
    .map_err(|(_c, msg)| msg)?;
    let env_id = ctx.env_id();
    let sub = ctx.sub().to_string();
    let sub_uuid = Uuid::parse_str(&sub).map_err(|_| "auth sub is not a UUID".to_string())?;

    // Bind the sub → email8 account id on a dedicated connection with
    // tenant context set (§4.3d - same connection as the data query).
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| format!("pool acquire: {e}"))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| format!("tenant context: {e}"))?;
    let account_id: (Uuid,) = sqlx::query_as(
        "SELECT id FROM email8.principals \
         WHERE env_id = $1 AND sentin8_auth_user_id = $2 LIMIT 1",
    )
    .bind(env_id)
    .bind(sub_uuid)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| "no mailbox account for this user (provisioning pending)".to_string())?;

    Ok(AccessAuth {
        user_sub: sub,
        env_id,
        account_id: account_id.0,
    })
}
