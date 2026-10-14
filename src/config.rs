// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! Email8:Access configuration — listener ports + platform URLs.

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone, Copy)]
pub struct ProtoListener {
    pub port: u16,
    pub implicit_tls: bool,
}

#[derive(Debug, Clone)]
pub struct AccessConfig {
    pub port: u16,
    pub database_url: String,
    pub store_url: String,
    pub sentin8_storage_url: String,
    /// IMAP (143 STARTTLS / 993 implicit).
    pub imap: ProtoListener,
    pub imaps: ProtoListener,
    /// POP3 (110 STLS / 995 implicit).
    pub pop3: ProtoListener,
    pub pop3s: ProtoListener,
    /// ManageSieve (4190).
    pub sieve: ProtoListener,
    /// Valkey URL for the listener-map publisher (gate discovery).
    pub valkey_url: String,
    pub sentin8_auth_client: AuthClient,
}

impl AccessConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env_u16("EMAIL8_ACCESS_PORT", 0),
            database_url: env_string("EMAIL8_ACCESS_DATABASE_URL")
                .or_else(|| env_string("DATABASE_URL"))
                .unwrap_or_else(|| sentin8::config::Sentin8Config::default_database_url().to_string()),
            store_url: env_string("EMAIL8_STORE_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("email8-store"))),
            sentin8_storage_url: env_string("SENTIN8_STORAGE_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("storage"))),
            // Raw listeners default to OS-EPHEMERAL (port 0): with the
            // Gate owning the well-known ports, concurrent instances
            // (rolling upgrades) must never contend for a fixed port.
            // Each instance publishes its actual listener map to Valkey
            // (gate reads it). EMAIL8_ACCESS_*_PORT env (dev direct-bind
            // mode) pins a port explicitly.
            imap: ProtoListener { port: env_u16("EMAIL8_ACCESS_IMAP_PORT", 0), implicit_tls: false },
            imaps: ProtoListener { port: env_u16("EMAIL8_ACCESS_IMAPS_PORT", 0), implicit_tls: true },
            pop3: ProtoListener { port: env_u16("EMAIL8_ACCESS_POP3_PORT", 0), implicit_tls: false },
            pop3s: ProtoListener { port: env_u16("EMAIL8_ACCESS_POP3S_PORT", 0), implicit_tls: true },
            sieve: ProtoListener { port: env_u16("EMAIL8_ACCESS_SIEVE_PORT", 0), implicit_tls: false },
            valkey_url: env_string("VALKEY_URL")
                .or_else(|| env_string("SENTIN8_VALKEY_URL"))
                .unwrap_or_else(|| sentin8::config::Sentin8Config::default_valkey_url().to_string()),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env_string("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}