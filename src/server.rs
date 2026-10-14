// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Email8:Access — HTTP health + raw-TCP listeners.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::config::AccessConfig;

/// Service state: the service config + the shell `ServiceCore`
/// (pool + Sentin8:Policy engine + shared admin surface — Phase 28 §3.6).
/// The engine inside `core.admin` is the SAME instance the step-5 gate
/// evaluates, so admin writes and request-time decisions agree.
/// (`ServiceCore` is not `Clone`; `Arc` gives the cheap state clone.)
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AccessConfig>,
    pub pool: sqlx::PgPool,
    pub core: std::sync::Arc<sentin8::shell::ServiceCore>,
}

pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let config = Arc::new(AccessConfig::from_env());
    let core = std::sync::Arc::new(core);
    let state = AppState { config: config.clone(), pool: core.pool.clone(), core };

    // Sentin8:Policy (Phase 28, §4.2b — shell-owned boot): the shell's
    // boot step 8 already booted the engine (refuse-to-start, shared deps,
    // hot-reload consumer, stat emitter). Services only consume it.

    // Raw-TCP protocol listeners (access design §2). Port 0 = OS-ephemeral
    // bind (the Gate owns the well-known ports; each instance publishes
    // its actual listener map to Valkey for gate discovery). An env-pinned
    // port (dev direct-bind mode) is honored as-is.
    let mut bound = Vec::new();
    bound.extend(spawn_listener(config.clone(), state.pool.clone(), state.core.admin.policy.clone(), config.imap, Proto::Imap, "imap").await?);
    bound.extend(spawn_listener(config.clone(), state.pool.clone(), state.core.admin.policy.clone(), config.imaps, Proto::Imaps, "imaps").await?);
    bound.extend(spawn_listener(config.clone(), state.pool.clone(), state.core.admin.policy.clone(), config.pop3, Proto::Pop3, "pop3").await?);
    bound.extend(spawn_listener(config.clone(), state.pool.clone(), state.core.admin.policy.clone(), config.pop3s, Proto::Pop3s, "pop3s").await?);
    bound.extend(spawn_listener(config.clone(), state.pool.clone(), state.core.admin.policy.clone(), config.sieve, Proto::Sieve, "sieve").await?);

    // Publish the actual listener map for the gate (best-effort).
    let instance_key = format!(
        "{}:{}",
        std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_else(|_| "127.0.0.1".into()),
        std::env::var("EMAIL8_ACCESS_PORT").unwrap_or_else(|_| "?".into()),
    );
    email8::gate::contracts::listener_registry::publish(
        &config.valkey_url,
        "email8:access",
        "email8-access",
        &instance_key,
        &bound,
    )
    .await;
    // Un-publish on graceful stop (gate design §3.3).
    email8::gate::contracts::listener_registry::spawn_unpublish_on_shutdown(
        config.valkey_url.clone(),
        "email8:access",
        "email8-access",
        instance_key,
    );

    Ok(state)
}

/// Consume a leading PROXY protocol v2 header from `stream` when the
/// listener is gate-served (`EMAIL8_ACCESS_ACCEPT_PROXY=true`). Returns
/// the real client address (or `None` when parsing is disabled).
/// A malformed header is a protocol desync — the caller must drop the
/// connection.
pub async fn strip_proxy_v2<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Option<std::net::SocketAddr>, email8::gate::contracts::proxy_parse::ProxyV2Error> {
    use tokio::io::AsyncReadExt;
    if !email8::gate::contracts::proxy_parse::accept_proxy_from_env("EMAIL8_ACCESS_ACCEPT_PROXY") {
        return Ok(None);
    }
    let mut head = [0u8; 16];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| email8::gate::contracts::proxy_parse::ProxyV2Error::Truncated { needed: 16, got: 0 })?;
    let addr_len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut block = vec![0u8; addr_len];
    stream
        .read_exact(&mut block)
        .await
        .map_err(|_| email8::gate::contracts::proxy_parse::ProxyV2Error::Truncated { needed: addr_len, got: 0 })?;
    let mut full = Vec::with_capacity(16 + addr_len);
    full.extend_from_slice(&head);
    full.extend_from_slice(&block);
    let (addrs, _len) = email8::gate::contracts::proxy_parse::parse_v2_header(&full)?;
    tracing::debug!(client = %addrs.source, dst = %addrs.destination, "email8:access: PROXY v2 consumed");
    Ok(Some(addrs.source))
}

#[derive(Clone, Copy, Debug)]
enum Proto {
    Imap,
    Imaps,
    Pop3,
    Pop3s,
    Sieve,
}

async fn spawn_listener(
    config: Arc<AccessConfig>,
    pool: sqlx::PgPool,
    engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    spec: crate::config::ProtoListener,
    proto: Proto,
    proto_name: &'static str,
) -> anyhow::Result<Vec<email8::gate::contracts::listener_registry::BoundListener>> {
    // Bind: port 0 → OS-assigned ephemeral (the default under the gate);
    // an env-pinned port binds as-is (dev direct-bind mode).
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", spec.port)).await?;
    let bound_port = listener.local_addr()?.port();
    let cfg = config.clone();
    tokio::spawn(async move {
        tracing::info!(port = bound_port, ?proto, implicit_tls = spec.implicit_tls, "email8:access: listener bound");
        loop {
            match listener.accept().await {
                Ok((socket, _peer)) => {
                    let cfg = cfg.clone();
                    let pool = pool.clone();
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        match proto {
                            Proto::Imap => {
                                let session =
                                    crate::imap_session::ImapSession::new(socket, cfg, pool, engine);
                                let _ = session.run().await;
                            }
                            // POP3 (RFC 1939/2449) + ManageSieve (RFC 5804)
                            // — full protocol surfaces over Store's data API.
                            Proto::Pop3 | Proto::Pop3s => {
                                let session =
                                    crate::pop3_session::Pop3Session::new(socket, cfg, pool, engine);
                                let _ = session.run().await;
                            }
                            Proto::Imaps => {
                                let session =
                                    crate::imap_session::ImapSession::new(socket, cfg, pool, engine);
                                let _ = session.run().await;
                            }
                            Proto::Sieve => {
                                let session =
                                    crate::sieve_session::SieveSession::new(socket, cfg, pool, engine);
                                let _ = session.run().await;
                            }
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "email8:access: accept failed"),
            }
        }
    });
    Ok(vec![email8::gate::contracts::listener_registry::BoundListener {
        proto: proto_name,
        port: bound_port,
        implicit_tls: spec.implicit_tls,
    }])
}

pub fn routes(router: axum::Router<AppState>) -> axum::Router<AppState> {
    // DAV surface (CalDAV/CardDAV/WebDAV, access design §6) — the
    // any-method dispatcher owns OPTIONS/PROPFIND/GET/PUT/DELETE/
    // MKCOL/MKCALENDAR/REPORT. NO CorsLayer here: tower-http treats every
    // OPTIONS as a preflight and responds itself (empty 200, no DAV/
    // Allow headers), which would hide the RFC 4918 §10.1 advertisement.
    // DAV clients are native apps, not browsers — CORS is not applicable
    // on this surface (access design §2); the JMAP/HTTP surface for
    // browsers goes through the BFF, which owns CORS.
    router
        .route("/v1/health", get(health))
        .route(
            "/dav/{*path}",
            axum::routing::any(crate::dav::dispatch).options(crate::dav::dispatch),
        )
        .route("/dav", axum::routing::any(crate::dav::dispatch_root).options(crate::dav::dispatch_root))
        .route("/dav/", axum::routing::any(crate::dav::dispatch_root).options(crate::dav::dispatch_root))
        // ── Sentin8:Policy admin API (Phase 28 §3.6 — shared
        // implementation; handlers generic over this state via
        // HasPolicyAdmin).
        .route("/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<AppState>))
        .route("/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<AppState>)
                .put(sentin8::shield::admin::put_policy_set::<AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<AppState>))
        .route("/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<AppState>))
        .route("/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<AppState>))
        .route("/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<AppState>))
        .route("/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<AppState>))
        .route("/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<AppState>)
                .put(sentin8::shield::admin::put_relation::<AppState>)
                .delete(sentin8::shield::admin::delete_relation::<AppState>))
        .route("/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<AppState>))
        .route("/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<AppState>)
                .put(sentin8::shield::admin::put_attribute::<AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<AppState>))
}

/// Shared policy-admin surface accessor (Phase 28 §3.6): the boot
/// loaded the engine into `core.admin`; the shared handlers extract it
/// via `HasPolicyAdmin` so the admin surface and the request path
/// evaluate the SAME cache.
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.core.admin
    }
}

async fn health() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "email8:access",
        "version": sentin8::build_info::id(),
            "build": sentin8::build_info::build_hash(),
    }))
}