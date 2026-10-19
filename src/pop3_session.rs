// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! POP3 session (RFC 1939 + RFC 2449 CAPA/STLS + RFC 1939 UIDL semantics
//! adapted to the changelog-backed store: UIDL = `{uid_validity}{uid}`).
//!
//! INBOX-only projection (access design §4): STAT/LIST/UIDL/RETR/TOP
//! read through Store's data API; DELE marks ids; QUIT applies the
//! batch expunge via the Store API; RSET reverts. APOP rejected (parity
//! with the legacy server).
use uuid::Uuid;

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::AccessAuth;
use crate::config::AccessConfig;

pub struct Pop3Session<S> {
    stream: S,
    config: Arc<AccessConfig>,
    pool: sqlx::PgPool,
    /// The service policy engine (step-5 gate; Phase 28).
    engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    auth: Option<AccessAuth>,
    /// INBOX message listing: (email_id, imap_uid, size).
    inbox: Vec<(Uuid, i64, i64)>,
    /// Indices marked DELE (into `inbox`).
    deleted: Vec<usize>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Pop3Session<S> {
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
            inbox: Vec::new(),
            deleted: Vec::new(),
        }
    }

    pub async fn run(mut self) -> std::io::Result<()> {
        // PROXY v2: consume the gate's header before the +OK greeting.
        if let Err(e) = crate::server::strip_proxy_v2(&mut self.stream).await {
            tracing::warn!(error = %e, "email8:access: PROXY v2 parse failed - dropping");
            return Ok(());
        }
        self.write_line("+OK Email8 POP3 at your service.").await?;
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            // Line-at-a-time protocol (no literal continuations).
            let line = loop {
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    break String::from_utf8_lossy(&line).trim().to_string();
                }
                let n = tokio::time::timeout(
                    std::time::Duration::from_secs(600),
                    self.stream.read(&mut chunk),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "session timed out")
                })??;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            };
            let mut words = line.split_whitespace();
            let Some(cmd) = words.next().map(|c| c.to_ascii_uppercase()) else {
                continue;
            };
            let arg1 = words.next();
            let arg2 = words.next();
            match cmd.as_str() {
                "CAPA" => {
                    self.write_line("+OK Capability list follows").await?;
                    self.write_line("STLS").await?;
                    self.write_line("UIDL").await?;
                    self.write_line("TOP").await?;
                    self.write_line("USER").await?;
                    self.write_line("PIPELINING").await?;
                    self.write_line("UTF8").await?;
                    self.write_line("IMPLEMENTATION Email8").await?;
                    self.write_line(".").await?;
                }
                "STLS" => {
                    // TLS wrap is listener-owned (platform gap G1).
                    self.write_line("-ERR TLS upgrade requires the platform raw-TCP TLS mode")
                        .await?;
                }
                "AUTH" => {
                    self.write_line("-ERR Use USER/PASS with the platform token")
                        .await?;
                }
                "USER" => {
                    let Some(_user) = arg1 else {
                        self.write_line("-ERR USER requires a name").await?;
                        continue;
                    };
                    self.write_line("+OK").await?;
                }
                "PASS" => {
                    // The PASS field carries the Sentin8:Auth bearer token
                    // (the §4.4 bridge - same as IMAP LOGIN).
                    let Some(token) = arg1 else {
                        self.write_line("-ERR PASS requires the token").await?;
                        continue;
                    };
                    match crate::auth::verify(
                        &self.pool,
                        &self.config,
                        &self.engine,
                        token,
                        "email8:mail:read",
                    )
                    .await
                    {
                        Ok(a) => {
                            self.auth = Some(a);
                            self.reload_inbox().await;
                            self.write_line("+OK Logged in.").await?;
                        }
                        Err(e) => {
                            self.write_line(&format!("-ERR Authentication failed: {e}"))
                                .await?;
                        }
                    }
                }
                "STAT" if self.auth.is_some() => {
                    let total: i64 = self
                        .inbox
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| !self.deleted.contains(i))
                        .count() as i64;
                    let bytes: i64 = self
                        .inbox
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| !self.deleted.contains(i))
                        .map(|(_, (_, _, s))| s)
                        .sum();
                    self.write_line(&format!("+OK {total} {bytes}")).await?;
                }
                "LIST" if self.auth.is_some() => {
                    let visible: Vec<(usize, i64)> = (0..self.inbox.len())
                        .filter(|i| !self.deleted.contains(i))
                        .map(|i| (i, self.inbox[i].2))
                        .collect();
                    let total: i64 = visible.iter().map(|(_, s)| s).sum();
                    self.write_line(&format!("+OK {} messages ({total} octets)", visible.len()))
                        .await?;
                    for (idx, size) in visible {
                        self.write_line(&format!("{} {size}", idx + 1)).await?;
                    }
                    self.write_line(".").await?;
                }
                "UIDL" if self.auth.is_some() => match arg1 {
                    None => {
                        self.write_line("+OK").await?;
                        let inbox = self.inbox.clone();
                        for (idx, (email_id, uid, _)) in inbox.iter().enumerate() {
                            if self.deleted.contains(&idx) {
                                continue;
                            }
                            self.write_line(&format!("{} {}", idx + 1, uidl(*email_id, *uid)))
                                .await?;
                        }
                        self.write_line(".").await?;
                    }
                    Some(n) => match self.msg_index(n) {
                        Some(idx) => {
                            let (email_id, uid, _) = self.inbox[idx];
                            self.write_line(&format!("+OK {} {}", idx + 1, uidl(email_id, uid)))
                                .await?;
                        }
                        None => self.write_line("-ERR no such message").await?,
                    },
                },
                "RETR" if self.auth.is_some() => {
                    let Some(n) = arg1 else {
                        self.write_line("-ERR RETR requires a message number")
                            .await?;
                        continue;
                    };
                    match self
                        .fetch_raw(self.inbox.get(self.msg_index(n).unwrap_or(usize::MAX)))
                        .await
                    {
                        Ok(Some(raw)) => {
                            self.write_line(&format!("+OK {} octets", raw.len()))
                                .await?;
                            // Dot-stuffing + terminator.
                            self.write_dotted(&raw).await?;
                        }
                        _ => self.write_line("-ERR no such message").await?,
                    }
                }
                "TOP" if self.auth.is_some() => {
                    let (Some(n), Some(k)) = (arg1, arg2) else {
                        self.write_line("-ERR TOP requires n k").await?;
                        continue;
                    };
                    let Ok(k) = k.parse::<usize>() else {
                        self.write_line("-ERR bad k").await?;
                        continue;
                    };
                    match self
                        .fetch_raw(self.inbox.get(self.msg_index(n).unwrap_or(usize::MAX)))
                        .await
                    {
                        Ok(Some(raw)) => {
                            self.write_line("+OK").await?;
                            let window = top_window(&raw, k);
                            self.write_dotted(&window).await?;
                        }
                        _ => self.write_line("-ERR no such message").await?,
                    }
                }
                "DELE" if self.auth.is_some() => {
                    let Some(n) = arg1 else {
                        self.write_line("-ERR DELE requires a message number")
                            .await?;
                        continue;
                    };
                    match self.msg_index(n) {
                        Some(idx) if !self.deleted.contains(&idx) => {
                            self.deleted.push(idx);
                            self.write_line("+OK message deleted").await?;
                        }
                        _ => self.write_line("-ERR no such message").await?,
                    }
                }
                "RSET" if self.auth.is_some() => {
                    self.deleted.clear();
                    self.write_line("+OK").await?;
                }
                "NOOP" => self.write_line("+OK").await?,
                "UTF8" => self.write_line("+OK").await?,
                "QUIT" => {
                    if let Some(auth) = &self.auth {
                        if !self.deleted.is_empty() {
                            self.apply_deletes(auth).await;
                        }
                    }
                    self.write_line("+OK Email8 POP3 closing.").await?;
                    return Ok(());
                }
                _ => {
                    if self.auth.is_none()
                        && !matches!(
                            cmd.as_str(),
                            "CAPA" | "QUIT" | "NOOP" | "STLS" | "USER" | "PASS" | "AUTH"
                        )
                    {
                        self.write_line("-ERR Authenticate first").await?;
                    } else {
                        self.write_line("-ERR Unknown command").await?;
                    }
                }
            }
        }
    }

    fn msg_index(&self, n: &str) -> Option<usize> {
        let idx: usize = n.parse().ok()?;
        let real = idx.checked_sub(1)?;
        (real < self.inbox.len()).then_some(real)
    }

    /// Reload the INBOX listing from Store.
    async fn reload_inbox(&mut self) {
        let Some(auth) = &self.auth else { return };
        self.inbox = fetch_inbox(self, auth).await;
        self.deleted.clear();
    }

    /// Fetch a raw message from the Store data API.
    async fn fetch_raw(&self, entry: Option<&(Uuid, i64, i64)>) -> Result<Option<Vec<u8>>, ()> {
        let Some(auth) = &self.auth else {
            return Ok(None);
        };
        let Some((email_id, _, _)) = entry else {
            return Ok(None);
        };
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/email/{}/{}/{email_id}",
            self.config.store_url.trim_end_matches('/'),
            auth.env_id,
            auth.account_id
        );
        let resp = client.get(&url).send().await.map_err(|_| ())?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body: serde_json::Value = resp.json().await.map_err(|_| ())?;
        // The Store email endpoint returns metadata + the raw blob
        // base64-encoded (`raw_b64`).
        let raw = body
            .get("raw_b64")
            .and_then(|v| v.as_str())
            .and_then(|b| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(b).ok()
            })
            .unwrap_or_default();
        Ok((!raw.is_empty()).then_some(raw))
    }

    /// QUIT-time expunge: delete marked messages through the Store API.
    async fn apply_deletes(&self, auth: &AccessAuth) {
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/emails/destroy",
            self.config.store_url.trim_end_matches('/'),
        );
        let ids: Vec<Uuid> = self
            .deleted
            .iter()
            .filter_map(|i| self.inbox.get(*i).map(|(id, _, _)| *id))
            .collect();
        if ids.is_empty() {
            return;
        }
        let _ = client
            .post(&url)
            .json(&serde_json::json!({
                "env_id": auth.env_id,
                "account_id": auth.account_id,
                "mailbox_id": 0, // INBOX
                "email_ids": ids,
            }))
            .send()
            .await;
    }

    async fn write_line(&mut self, s: &str) -> std::io::Result<()> {
        self.stream.write_all(format!("{s}\r\n").as_bytes()).await
    }

    /// Write a dot-stuffed body + the `.` terminator (RFC 1939 §3).
    async fn write_dotted(&mut self, raw: &[u8]) -> std::io::Result<()> {
        for line in raw.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.starts_with(b".") {
                self.stream.write_all(b".").await?;
            }
            self.stream.write_all(line).await?;
            self.stream.write_all(b"\r\n").await?;
        }
        self.stream.write_all(b".\r\n").await
    }
}

fn uidl(email_id: Uuid, uid: i64) -> String {
    // Legacy parity: a stable unique id combining mailbox validity and
    // the IMAP UID (the inbox uid_validity is folded into the id).
    format!("{email_id:012x}{uid}")
}

/// The TOP n k window: headers + first k body lines.
fn top_window(raw: &[u8], k: usize) -> Vec<u8> {
    let split = memchr::memmem::find(raw, b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(raw.len());
    let (headers, body) = raw.split_at(split.min(raw.len()));
    let mut out = headers.to_vec();
    for (i, line) in body.split(|&b| b == b'\n').enumerate() {
        if i >= k {
            break;
        }
        out.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Fetch the INBOX listing (id, uid, size) via the Store data API.
async fn fetch_inbox(
    session: &Pop3Session<impl AsyncRead + AsyncWrite + Unpin>,
    auth: &AccessAuth,
) -> Vec<(Uuid, i64, i64)> {
    let client = crate::store_http::store_client().await;
    let url = format!(
        "{}/v1/internal/mailbox/emails?env_id={}&account_id={}&mailbox_id=0",
        session.config.store_url.trim_end_matches('/'),
        auth.env_id,
        auth.account_id
    );
    let Ok(resp) = client.get(&url).send().await else {
        return Vec::new();
    };
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return Vec::new();
    };
    body.get("items")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some((
                        m.get("id")?.as_str()?.parse().ok()?,
                        m.get("uid")?.as_i64()?,
                        m.get("size")?.as_i64()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uidl_is_stable_and_unique() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_ne!(uidl(a, 10), uidl(b, 10));
        assert_ne!(uidl(a, 10), uidl(a, 11));
    }

    #[test]
    fn top_window_limits_body_lines() {
        let raw = b"From: a@b.c\r\nSubject: s\r\n\r\nline1\r\nline2\r\nline3\r\n";
        let w = top_window(raw, 2);
        let s = String::from_utf8_lossy(&w);
        assert!(s.contains("Subject: s"));
        assert!(s.contains("line1"));
        assert!(s.contains("line2"));
        assert!(!s.contains("line3"));
    }
}
