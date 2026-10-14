// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Email8:Access — legacy-protocol front-end services.
//!
//! See `email8/design/sentin8-email8-access-technical-design.md`.
//!
//! Raw-TCP listeners (IMAP 143/993, POP3 110/995, ManageSieve 4190) run as
//! dedicated tasks over the platform TLS surface; DAV is served over HTTPS
//! via the shell router. All data access flows through Email8:Store's
//! data API — Access never writes mail tables directly.

#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod dav;
mod imap_session;
mod openapi;
#[allow(dead_code)]
mod pop3_session;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod sieve_session;
#[allow(dead_code)]
mod store_http;

use utoipa::OpenApi;

/// mimalloc global allocator (design §6 D13) — IMAP/POP3/ManageSieve
/// session tasks and the DAV HTTPS surface allocate through it.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("email8:access", "EMAIL8_ACCESS")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            // DAV requires the service's own OPTIONS handler (it must
            // advertise the `DAV`/`Allow` headers per RFC 4918 §10.1);
            // the shell's default CORS layer intercepts every OPTIONS
            // preflight-style and hides them, so opt out of the default
            // layers and keep the CORS layer inside the DAV-owning
            // router instead.
            .with_own_layers()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::AccessOpenApi::openapi()),
    )
    .await
}
