// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! Certificate-presenting HTTP client for internal Store data-API calls
//! (design `sentin8-email8-technical-design.md` service-to-service row;
//! CERTFREE-4V). The Access service presents its own Acme-issued
//! workload certificate (`CN=m2m-email8:access`) in the TLS handshake -
//! Store's TLS layer authenticates it and its internal-API gate resolves
//! the workload against the enroll-published registry map. No M2M token
//! exists on this path.

use std::sync::OnceLock;

/// The shared cert-presenting client (built once per process; clone-cheap).
static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// The shared cert-presenting Store client. Falls back to a plain HTTP
/// client when the workload certificate cannot be ensured yet (Acme
/// still coming up at first boot): Store rejects a tokenless client
/// loudly at its authorization gate and the next session retries -
/// fail-soft, like a Store outage.
pub async fn store_client() -> reqwest::Client {
    if let Some(cached) = CLIENT.get() {
        return cached.clone();
    }
    let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer());
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let built = match sentin8::auth::m2m::ensure_workload_certificate(
        &issuer,
        "email8:access",
        &ca_cert_path,
    )
    .await
    {
        Ok(cert) => {
            let mtls = sentin8::middleware::mtls::MtlsConfig::new(
                &cert.ca_cert_path,
                &cert.cert_path,
                &cert.key_path,
            );
            match sentin8::middleware::mtls::build_mtls_client(&mtls) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "email8:access: store mTLS transport unavailable - degraded");
                    reqwest::Client::new()
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "email8:access: workload certificate not ready - store calls degraded");
            reqwest::Client::new()
        }
    };
    let _ = CLIENT.set(built.clone());
    built
}
