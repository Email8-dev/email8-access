// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! ManageSieve session (RFC 5804) - script CRUD over the Store data
//! API with the untrusted compile check from the `email8-sieve` crate.
//! CAPABILITY advertises the registered extension set; PUTSCRIPT
//! compiles + stores; SETACTIVE flips the principal's active script.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::AccessAuth;
use crate::config::AccessConfig;

pub struct SieveSession<S> {
    stream: S,
    config: Arc<AccessConfig>,
    pool: sqlx::PgPool,
    /// The service policy engine (step-5 gate; Phase 28).
    engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    auth: Option<AccessAuth>,
    /// Literal continuation: (pending bytes, collected).
    literal: Option<(usize, Vec<u8>)>,
    buffer: Vec<u8>,
    /// Script name for an in-flight PUTSCRIPT literal (None = CHECKSCRIPT).
    pending_script: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SieveSession<S> {
    pub fn new(
        stream: S,
        config: Arc<AccessConfig>,
        pool: sqlx::PgPool,
        engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    ) -> Self {
        Self {
            stream,
            config,
            pool,
            engine,
            auth: None,
            literal: None,
            buffer: Vec::new(),
            pending_script: None,
        }
    }

    pub async fn run(mut self) -> std::io::Result<()> {
        // PROXY v2 (gate design §3.3): consume the gate's header before
        // the capability greeting.
        if let Err(e) = crate::server::strip_proxy_v2(&mut self.stream).await {
            tracing::warn!(error = %e, "email8:access: PROXY v2 parse failed - dropping");
            return Ok(());
        }
        // RFC 5804 greeting: capabilities in quoted strings, OK last.
        let caps: Vec<String> = email8::sieve::SIEVE_EXTENSIONS
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect();
        self.write_line(&format!(
            "\"IMPLEMENTATION\" \"Email8 ManageSieve\"\r\n\"SASL\" \"XOAUTH2 OAUTHBEARER\"\r\n\"VERSION\" \"1.0\"\r\n{}",
            caps.join("\r\n")
        ))
        .await?;
        self.write_line("OK").await?;

        let mut chunk = [0u8; 4096];
        loop {
            // Literal mode: consume exactly N bytes.
            if let Some((n, collected)) = &mut self.literal {
                let need = *n - collected.len();
                let window_len = need.min(chunk.len());
                let got = tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    self.stream.read(&mut chunk[..window_len]),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "literal timed out")
                })??;
                if got == 0 {
                    return Ok(());
                }
                collected.extend_from_slice(&chunk[..got]);
                if collected.len() >= *n {
                    let collected = self.literal.take().unwrap().1;
                    self.handle_literal_done(collected).await?;
                }
                continue;
            }
            let got = tokio::time::timeout(
                std::time::Duration::from_secs(600),
                self.stream.read(&mut chunk),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "session timed out")
            })??;
            if got == 0 {
                return Ok(());
            }
            self.buffer.extend_from_slice(&chunk[..got]);
            while let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..=pos).collect();
                let line = String::from_utf8_lossy(&line).trim().to_string();
                if self.handle_line(line).await? {
                    return Ok(());
                }
            }
        }
    }

    /// Handle one command line. Returns true on LOGOUT.
    async fn handle_line(&mut self, line: String) -> std::io::Result<bool> {
        let mut words = line.splitn(2, ' ');
        let cmd = words.next().unwrap_or_default().to_ascii_uppercase();
        let rest = words.next().unwrap_or_default().trim().to_string();
        match cmd.as_str() {
            "CAPABILITY" => {
                self.write_line(&format!(
                    "\"IMPLEMENTATION\" \"Email8 ManageSieve\"\r\n\"SASL\" \"XOAUTH2 OAUTHBEARER\"\r\n\"SIEVE\" {}",
                    email8::sieve::SIEVE_EXTENSIONS.join(" ")
                ))
                .await?;
                self.write_line("OK").await?;
            }
            "NOOP" => self.write_line("OK").await?,
            "LOGOUT" => {
                self.write_line("OK \"Bye\"").await?;
                return Ok(true);
            }
            "STARTTLS" => {
                self.write_line("NO \"TLS requires the platform raw-TCP TLS mode\"")
                    .await?;
            }
            "AUTHENTICATE" => {
                // XOAUTH2/OAUTHBEARER: the b64 token is the next word (or
                // a continuation when absent).
                let mut parts = rest.split_whitespace();
                let mechanism = parts.next().unwrap_or_default().to_ascii_uppercase();
                let b64 = parts.next().unwrap_or_default().to_string();
                if b64.is_empty() {
                    self.write_line("+ ").await?; // continuation request
                    return Ok(false);
                }
                let token = crate::auth::decode_xoauth2(&b64).unwrap_or_default();
                let _ = mechanism;
                match crate::auth::verify(
                    &self.pool,
                    &self.config,
                    &self.engine,
                    &token,
                    "email8:sieve:manage",
                )
                .await
                {
                    Ok(a) => {
                        self.auth = Some(a);
                        self.write_line("OK").await?;
                    }
                    Err(_) => self.write_line("NO \"Authentication failed\"").await?,
                }
            }
            _ if self.auth.is_none() => {
                self.write_line("NO \"Authenticate first\"").await?;
            }
            "HAVESPACE" => {
                // Quota check against the Store - permissive by default.
                self.write_line(&format!("OK {}", 1024 * 1024)).await?;
            }
            "LISTSCRIPTS" => match self.store_list_scripts().await {
                Ok(list) => {
                    for (name, active) in list {
                        if active {
                            self.write_line(&format!("\"{name}\" ACTIVE")).await?;
                        } else {
                            self.write_line(&format!("\"{name}\"")).await?;
                        }
                    }
                    self.write_line("OK").await?;
                }
                Err(e) => self.write_line(&format!("NO \"{e}\"")).await?,
            },
            "GETSCRIPT" => match self.store_get_script(rest.trim_matches('"')).await {
                Ok(Some(script)) => {
                    // Literal response: {n+}\r\n<bytes>\r\nOK
                    self.write_line(&format!("{{{}}}", script.len())).await?;
                    self.stream.write_all(&script).await?;
                    self.stream.write_all(b"\r\n").await?;
                    self.write_line("OK").await?;
                }
                _ => {
                    self.write_line("NO (NONEXISTENT) \"No such script\"")
                        .await?
                }
            },
            "PUTSCRIPT" => {
                // PUTSCRIPT "name" {n}\r\n<bytes> - the literal follows.
                let name = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
                let Some(size_str) = rest
                    .rsplit('{')
                    .next()
                    .and_then(|s| s.strip_suffix('+').or_else(|| s.strip_suffix('}')))
                else {
                    self.write_line("NO \"Expected {n+} literal\"").await?;
                    return Ok(false);
                };
                match size_str.parse::<usize>() {
                    Ok(n) if n <= 1024 * 1024 => {
                        self.pending_script = Some(name);
                        self.literal = Some((n, Vec::with_capacity(n)));
                        self.write_line("OK").await?; // ready-for-literal
                    }
                    _ => {
                        self.write_line("NO (QUOTA/MAXSIZE) \"Script too large\"")
                            .await?
                    }
                }
            }
            "CHECKSCRIPT" => {
                // Same literal flow; compiled then discarded.
                let Some(size_str) = rest
                    .rsplit('{')
                    .next()
                    .and_then(|s| s.strip_suffix('+').or_else(|| s.strip_suffix('}')))
                else {
                    self.write_line("NO \"Expected {n+} literal\"").await?;
                    return Ok(false);
                };
                match size_str.parse::<usize>() {
                    Ok(n) if n <= 1024 * 1024 => {
                        self.pending_script = None;
                        self.literal = Some((n, Vec::with_capacity(n)));
                        self.write_line("OK").await?;
                    }
                    _ => {
                        self.write_line("NO (QUOTA/MAXSIZE) \"Script too large\"")
                            .await?
                    }
                }
            }
            "SETACTIVE" => {
                let name = rest.trim_matches('"');
                if name.is_empty() {
                    // Deactivate.
                    if let Err(e) = self.store_set_active(None).await {
                        self.write_line(&format!("NO \"{e}\"")).await?;
                    } else {
                        self.write_line("OK").await?;
                    }
                } else if let Err(e) = self.store_set_active(Some(name)).await {
                    self.write_line(&format!("NO \"{e}\"")).await?;
                } else {
                    self.write_line("OK").await?;
                }
            }
            "DELETESCRIPT" => {
                let name = rest.trim_matches('"');
                match self.store_delete_script(name).await {
                    Ok(true) => self.write_line("OK").await?,
                    Ok(false) => {
                        self.write_line("NO (NONEXISTENT) \"No such script\"")
                            .await?
                    }
                    Err(e) => self.write_line(&format!("NO \"{e}\"")).await?,
                }
            }
            "RENAMESCRIPT" => {
                let mut parts = rest.splitn(2, ' ');
                let from = parts.next().unwrap_or_default().trim_matches('"');
                let to = parts.next().unwrap_or_default().trim_matches('"');
                match self.store_rename_script(from, to).await {
                    Ok(()) => self.write_line("OK").await?,
                    Err(e) => self.write_line(&format!("NO \"{e}\"")).await?,
                }
            }
            "UNAUTHENTICATE" => {
                self.auth = None;
                self.write_line("OK").await?;
            }
            _ => self.write_line("NO \"Unknown command\"").await?,
        }
        Ok(false)
    }

    /// Literal complete: compile (PUTSCRIPT/CHECKSCRIPT) then store.
    async fn handle_literal_done(&mut self, raw: Vec<u8>) -> std::io::Result<()> {
        let source = String::from_utf8_lossy(&raw).trim().to_string();
        // Untrusted compile check.
        match email8::sieve::compile(&source) {
            Ok(script) => {
                let name = self.pending_script.take();
                match name {
                    None => self.write_line("OK").await?, // CHECKSCRIPT
                    Some(name) => match self.store_put_script(&name, &source, &script).await {
                        Ok(()) => self.write_line("OK").await?,
                        Err(e) => self.write_line(&format!("NO \"{e}\"")).await?,
                    },
                }
            }
            Err(e) => {
                self.pending_script = None;
                self.write_line(&format!("NO \"Script compile failed: {e}\""))
                    .await?;
            }
        }
        Ok(())
    }

    async fn write_line(&mut self, s: &str) -> std::io::Result<()> {
        self.stream.write_all(format!("{s}\r\n").as_bytes()).await
    }

    async fn store_call(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<reqwest::Response, String> {
        let auth = self.auth.as_ref().ok_or("not authenticated")?;
        let url = format!("{}{path}", self.config.store_url.trim_end_matches('/'));
        let mut envelope = serde_json::json!({
            "env_id": auth.env_id,
            "account_id": auth.account_id,
        });
        // Merge the call-specific fields under the auth envelope.
        if let (Some(dst), Some(src)) = (envelope.as_object_mut(), body.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        let client = crate::store_http::store_client().await;
        client
            .post(&url)
            .json(&envelope)
            .send()
            .await
            .map_err(|e| e.to_string())
    }

    async fn store_list_scripts(&self) -> Result<Vec<(String, bool)>, String> {
        let resp = self
            .store_call("/v1/internal/sieve/list", serde_json::json!({}))
            .await?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body
            .get("items")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| {
                        Some((
                            s.get("name")?.as_str()?.to_string(),
                            s.get("is_active")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn store_get_script(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let resp = self
            .store_call(
                "/v1/internal/sieve/get",
                serde_json::json!({ "name": name }),
            )
            .await?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let Some(script) = body.get("source").and_then(|v| v.as_str()) else {
            return Ok(None);
        };
        Ok(Some(script.as_bytes().to_vec()))
    }

    async fn store_put_script(
        &self,
        name: &str,
        source: &str,
        _script: &email8::sieve::Script,
    ) -> Result<(), String> {
        let resp = self
            .store_call(
                "/v1/internal/sieve/put",
                serde_json::json!({ "name": name, "source": source }),
            )
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("store returned {}", resp.status()))
        }
    }

    async fn store_set_active(&self, name: Option<&str>) -> Result<(), String> {
        let resp = self
            .store_call(
                "/v1/internal/sieve/setactive",
                serde_json::json!({ "name": name }),
            )
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("store returned {}", resp.status()))
        }
    }

    async fn store_delete_script(&self, name: &str) -> Result<bool, String> {
        let resp = self
            .store_call(
                "/v1/internal/sieve/delete",
                serde_json::json!({ "name": name }),
            )
            .await?;
        Ok(resp.status().is_success())
    }

    async fn store_rename_script(&self, from: &str, to: &str) -> Result<(), String> {
        let resp = self
            .store_call(
                "/v1/internal/sieve/rename",
                serde_json::json!({ "from": from, "to": to }),
            )
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("store returned {}", resp.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sieve_extension_list_is_nonempty() {
        assert!(email8::sieve::SIEVE_EXTENSIONS.contains(&"fileinto"));
        assert!(email8::sieve::SIEVE_EXTENSIONS.contains(&"vacation"));
    }
}
