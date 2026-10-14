// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! IMAP session — P1 op set over Email8:Store's data API.
//!
//! Implements: greeting + capabilities, AUTHENTICATE/LOGIN via the SASL
//! bridge, LIST/LSUB, SELECT/EXAMINE, STATUS, NOOP/CHECK, LOGOUT.
//! FETCH/SEARCH/STORE/EXPUNGE/APPEND and QRESYNC/CONDSTORE/IDLE land
//! with Epic 4.1 (the change-log plumbing is already in Store).
use uuid::Uuid;

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use email8::imap_proto::{
    Element, FetchItem, Op, Receiver, SequenceSet, StoreItem, CAPABILITIES_POST_AUTH,
    CAPABILITIES_PRE_AUTH,
};

use crate::auth::AccessAuth;
use crate::config::AccessConfig;

pub struct ImapSession<S> {
    stream: S,
    receiver: Receiver,
    config: Arc<AccessConfig>,
    pool: sqlx::PgPool,
    /// The service policy engine (step-5 gate; Phase 28).
    engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    auth: Option<AccessAuth>,
    /// The SELECTed mailbox: (mailbox_id, uid_validity, uid_next).
    selected: Option<(Uuid, i64, i64)>,
    /// Message listing of the SELECTed mailbox: (email_id, uid).
    listing: Vec<(Uuid, i64)>,
    /// EXPUNGE-pending email ids (CLOSE/EXPUNGE applies).
    pending_expunge: Vec<Uuid>,
    /// The most recent APPEND literal bytes (set by the receiver loop).
    append_literal: Option<Vec<u8>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ImapSession<S> {
    pub fn new(
        stream: S,
        config: Arc<AccessConfig>,
        pool: sqlx::PgPool,
        engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    ) -> Self {
        Self {
            stream,
            receiver: Receiver::new(),
            config,
            pool,
            engine,
            auth: None,
            selected: None,
            listing: Vec::new(),
            pending_expunge: Vec::new(),
            append_literal: None,
        }
    }

    pub async fn run(mut self) -> std::io::Result<()> {
        // PROXY v2 (gate design §3.3): consume the gate's header before
        // the greeting when this listener is gate-served.
        if let Err(e) = crate::server::strip_proxy_v2(&mut self.stream).await {
            tracing::warn!(error = %e, "email8:access: PROXY v2 parse failed — dropping");
            return Ok(());
        }
        self.write_raw(&email8::imap_proto::greeting(
            "email8",
            CAPABILITIES_PRE_AUTH,
        ))
        .await?;
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(30 * 60),
                self.stream.read(&mut buf),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "session timed out")
            })??;
            if n == 0 {
                return Ok(());
            }
            for element in self.receiver.parse(&buf[..n]) {
                match element {
                    Element::LiteralContinuation { size } => {
                        self.write_raw(&format!("+ Ready for {size} bytes\r\n"))
                            .await?;
                    }
                    Element::Literal { data } => {
                        // The literal that follows an APPEND (or a SEARCH
                        // CHARSET phrase); sessions keep the most recent
                        // one for the APPEND handler.
                        self.append_literal = Some(data);
                    }
                    Element::Command(cmd) => {
                        if self.handle(cmd.op, &cmd.tag).await? {
                            return Ok(());
                        }
                    }
                    Element::Invalid(_) => {
                        self.write_raw(&email8::imap_proto::tagged_bad("*", "Invalid command"))
                            .await?;
                    }
                }
            }
        }
    }

    /// Returns `true` on LOGOUT.
    async fn handle(&mut self, op: Op, tag: &str) -> std::io::Result<bool> {
        // Pre-auth commands only (IMAP4rev2 §6 except SASL).
        let pre_auth_ok = matches!(
            op,
            Op::Capability
                | Op::Noop
                | Op::Logout
                | Op::StartTls
                | Op::Authenticate { .. }
                | Op::Login { .. }
                | Op::Id { .. }
                | Op::Enable { .. }
        );
        if self.auth.is_none() && !pre_auth_ok {
            self.write_raw(&email8::imap_proto::tagged_no(
                tag,
                "Please authenticate first",
            ))
            .await?;
            return Ok(false);
        }
        match op {
            Op::Logout => {
                self.write_raw(&email8::imap_proto::untagged("BYE Email8 IMAP closing"))
                    .await?;
                self.write_raw(&email8::imap_proto::tagged_ok(tag, "LOGOUT completed"))
                    .await?;
                return Ok(true);
            }
            Op::Capability => {
                let caps = if self.auth.is_some() {
                    CAPABILITIES_POST_AUTH
                } else {
                    CAPABILITIES_PRE_AUTH
                };
                self.write_raw(&email8::imap_proto::capability_line(caps))
                    .await?;
                self.write_raw(&email8::imap_proto::tagged_ok(tag, "CAPABILITY completed"))
                    .await?;
            }
            Op::Noop | Op::Check | Op::Done => {
                self.write_raw(&email8::imap_proto::tagged_ok(tag, "NOOP completed"))
                    .await?;
            }
            Op::Id { .. } => {
                self.write_raw(&email8::imap_proto::untagged(
                    "ID (\"name\" \"Email8\" \"version\" \"0.1.0\")",
                ))
                .await?;
                self.write_raw(&email8::imap_proto::tagged_ok(tag, "ID completed"))
                    .await?;
            }
            Op::StartTls => {
                // The listener owns the TLS swap (access design §2);
                // raw-TCP TLS upgrade is platform gap G1, wired at the
                // listener — the session just acknowledges readiness.
                self.write_raw(&email8::imap_proto::tagged_ok(
                    tag,
                    "Begin TLS negotiation now",
                ))
                .await?;
            }
            Op::Authenticate { mechanism, initial } => {
                let token = initial
                    .as_deref()
                    .and_then(crate::auth::decode_xoauth2)
                    .unwrap_or_default();
                let _ = mechanism;
                if token.is_empty() {
                    self.write_raw(&email8::imap_proto::tagged_no(
                        tag,
                        "[AUTHENTICATIONFAILED] SASL token required",
                    ))
                    .await?;
                } else {
                    self.finish_login(tag, &token).await?;
                }
            }
            Op::Login { password, .. } => {
                // The platform-native path: the password field carries
                // the Sentin8:Auth token (master design §4.4 SASL
                // bridge). A real-password LOGIN bridge is config-gated
                // off exactly like SMTP PLAIN.
                self.finish_login(tag, &password).await?;
            }
            Op::List { pattern, .. } | Op::Lsub { pattern, .. } => {
                let auth = self.auth.clone().unwrap();
                match self.list_mailboxes(&auth, &pattern).await {
                    Ok(lines) => {
                        for line in lines {
                            self.write_raw(&line).await?;
                        }
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "LIST completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("LIST failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Select { mailbox } | Op::Examine { mailbox } => {
                let auth = self.auth.clone().unwrap();
                match self.select_mailbox(&auth, &mailbox).await {
                    Ok(resp) => {
                        for line in resp {
                            self.write_raw(&line).await?;
                        }
                        self.write_raw(&email8::imap_proto::tagged_ok(
                            tag,
                            "[READ-WRITE] SELECT completed",
                        ))
                        .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("SELECT failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Close | Op::Unselect => {
                // CLOSE applies pending EXPUNGEs; UNSELECT forgets them.
                if matches!(op, Op::Close) {
                    let auth = self.auth.clone().unwrap();
                    if let Some((mailbox_id, _, _)) = self.selected {
                        if !self.pending_expunge.is_empty() {
                            let _ = self
                                .store_destroy_emails(&auth, mailbox_id, &self.pending_expunge)
                                .await;
                        }
                    }
                }
                self.selected = None;
                self.listing.clear();
                self.pending_expunge.clear();
                self.write_raw(&email8::imap_proto::tagged_ok(tag, "CLOSE completed"))
                    .await?;
            }
            Op::Status { mailbox, items } => {
                let auth = self.auth.clone().unwrap();
                match self.status_mailbox(&auth, &mailbox, &items).await {
                    Ok(line) => {
                        self.write_raw(&line).await?;
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "STATUS completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("STATUS failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Fetch {
                sequence,
                items,
                uid,
            } => {
                let Some((mailbox_id, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                match self
                    .op_fetch(&auth, mailbox_id, &sequence, &items, uid)
                    .await
                {
                    Ok(lines) => {
                        for line in lines {
                            self.write_raw(&line).await?;
                        }
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "FETCH completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("FETCH failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Store {
                sequence,
                items,
                silent,
                uid,
                ..
            } => {
                let Some((mailbox_id, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                match self
                    .op_store(&auth, mailbox_id, &sequence, &items, silent, uid)
                    .await
                {
                    Ok(()) => {
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "STORE completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("STORE failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Search { criteria } => {
                let Some((mailbox_id, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                match self.op_search(&auth, mailbox_id, &criteria).await {
                    Ok(ids) => {
                        self.write_raw(&email8::imap_proto::search_line(&ids))
                            .await?;
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "SEARCH completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("SEARCH failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Sort {
                keys,
                criteria,
                uid,
            } => {
                let Some((mailbox_id, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                match self.op_sort(&auth, mailbox_id, &keys, &criteria).await {
                    Ok(orders) => {
                        // * SORT (ids) — the id sequence per RFC 5256.
                        let value = if uid {
                            orders
                                .iter()
                                .map(|(_, u)| u.to_string())
                                .collect::<Vec<_>>()
                        } else {
                            orders
                                .iter()
                                .map(|(seq, _)| seq.to_string())
                                .collect::<Vec<_>>()
                        };
                        self.write_raw(&email8::imap_proto::untagged(format!(
                            "* SORT {}",
                            value.join(" ")
                        )))
                        .await?;
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "SORT completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("SORT failed: {e}"),
                        ))
                        .await?;
                    }
                }
                let _ = uid;
            }
            Op::Thread {
                algorithm,
                criteria,
                uid,
            } => {
                let Some((mailbox_id, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                match self
                    .op_thread(&auth, mailbox_id, &algorithm, &criteria)
                    .await
                {
                    Ok(groups) => {
                        // * THREAD (a b)(c d) — grouped member ids.
                        let rendered: Vec<String> = groups
                            .iter()
                            .map(|g| {
                                let members: Vec<String> = if uid {
                                    g.iter().map(|(_, u)| u.to_string()).collect()
                                } else {
                                    g.iter().map(|(seq, _)| seq.to_string()).collect()
                                };
                                format!("({})", members.join(" "))
                            })
                            .collect();
                        self.write_raw(&email8::imap_proto::untagged(format!(
                            "* THREAD {}",
                            rendered.join("")
                        )))
                        .await?;
                        self.write_raw(&email8::imap_proto::tagged_ok(tag, "THREAD completed"))
                            .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("THREAD failed: {e}"),
                        ))
                        .await?;
                    }
                }
                let _ = uid;
            }
            Op::Expunge { uids } => {
                let Some((mailbox_id, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                let targets: Vec<Uuid> = match &uids {
                    // UID EXPUNGE restricts to the listed uids.
                    Some(list) => self
                        .listing
                        .iter()
                        .filter(|(_, u)| list.iter().any(|x| x == &u.to_string()))
                        .map(|(id, _)| *id)
                        .collect(),
                    None => {
                        // \Deleted-marked messages (pending list).
                        self.pending_expunge.clone()
                    }
                };
                if !targets.is_empty() {
                    let _ = self.store_destroy_emails(&auth, mailbox_id, &targets).await;
                    // Untagged EXPUNGE per removed sequence number.
                    let listing = self.listing.clone();
                    for (seq, (id, _)) in listing.iter().enumerate() {
                        if targets.contains(id) {
                            self.write_raw(&email8::imap_proto::untagged(format!(
                                "EXPUNGE {}",
                                seq + 1
                            )))
                            .await?;
                        }
                    }
                    self.listing.retain(|(id, _)| !targets.contains(id));
                    self.pending_expunge.retain(|id| !targets.contains(id));
                }
                self.write_raw(&email8::imap_proto::tagged_ok(tag, "EXPUNGE completed"))
                    .await?;
            }
            Op::Copy {
                ref sequence,
                ref mailbox,
                uid,
            }
            | Op::Move {
                ref sequence,
                ref mailbox,
                uid,
            } => {
                let Some((src_mailbox, _, _)) = self.selected else {
                    self.write_raw(&email8::imap_proto::tagged_bad(tag, "No mailbox selected"))
                        .await?;
                    return Ok(false);
                };
                let auth = self.auth.clone().unwrap();
                let is_move = matches!(&op, Op::Move { .. });
                match self
                    .op_copy(&auth, src_mailbox, sequence, mailbox, uid, is_move)
                    .await
                {
                    Ok(()) => {
                        let label = if is_move { "MOVE" } else { "COPY" };
                        self.write_raw(&email8::imap_proto::tagged_ok(
                            tag,
                            format!("{label} completed"),
                        ))
                        .await?;
                    }
                    Err(e) => {
                        let label = if is_move { "MOVE" } else { "COPY" };
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("{label} failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Append { mailbox, .. } => {
                // The receiver has already inlined the literal bytes into
                // the reconstructed command line; the APPEND op carries
                // the mailbox + flags + size. The raw bytes flow through
                // the store endpoints (blob → ingest).
                let auth = self.auth.clone().unwrap();
                match self.op_append(&auth, &mailbox).await {
                    Ok(appenduid) => {
                        let extra = appenduid
                            .map(|u| format!(" [APPENDUID 1 {u}]"))
                            .unwrap_or_default();
                        self.write_raw(&email8::imap_proto::tagged_ok(
                            tag,
                            format!("{extra}APPEND completed"),
                        ))
                        .await?;
                    }
                    Err(e) => {
                        self.write_raw(&email8::imap_proto::tagged_no(
                            tag,
                            format!("APPEND failed: {e}"),
                        ))
                        .await?;
                    }
                }
            }
            Op::Idle => {
                // IDLE: push exists via the changelog SSE stream (Store);
                // the session acknowledges and ends the idle on DONE.
                self.write_raw(&email8::imap_proto::untagged("OK IDLE started"))
                    .await?;
                // The receiver yields Op::Done on the DONE line.
            }
            Op::Enable { capabilities } => {
                let supported: Vec<String> = capabilities
                    .iter()
                    .filter(|c| {
                        matches!(
                            c.to_ascii_uppercase().as_str(),
                            "QRESYNC" | "CONDSTORE" | "UTF8=ACCEPT" | "IMAP4REV2" | "UIDPLUS"
                        )
                    })
                    .cloned()
                    .collect();
                let enabled = if supported.is_empty() {
                    String::new()
                } else {
                    format!(" [ENABLED {}]", supported.join(" "))
                };
                self.write_raw(&email8::imap_proto::tagged_ok(
                    tag,
                    format!("{enabled}ENABLE completed"),
                ))
                .await?;
            }
            Op::Unsupported { name } => {
                self.write_raw(&email8::imap_proto::tagged_bad(
                    tag,
                    format!("{name} not supported"),
                ))
                .await?;
            }
            _ => {
                self.write_raw(&email8::imap_proto::tagged_bad(
                    tag,
                    "Command not implemented yet",
                ))
                .await?;
            }
        }
        Ok(false)
    }

    async fn finish_login(&mut self, tag: &str, token: &str) -> std::io::Result<()> {
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
                self.write_raw(&email8::imap_proto::tagged_ok(
                    tag,
                    "[CAPABILITY IMAP4rev2 IMAP4rev1 AUTH=XOAUTH2] LOGIN completed",
                ))
                .await?;
            }
            Err(e) => {
                self.write_raw(&email8::imap_proto::tagged_no(
                    tag,
                    format!("[AUTHENTICATIONFAILED] {e}"),
                ))
                .await?;
            }
        }
        Ok(())
    }

    // ── Store-backed operations ────────────────────────────────────────

    // ── Store-backed operations ────────────────────────────────────────

    /// Fetch the account's mailboxes from Store (typed JSON array).
    async fn store_mailboxes(&self, auth: &AccessAuth) -> Result<serde_json::Value, String> {
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/mailboxes?env_id={}&account_id={}",
            self.config.store_url.trim_end_matches('/'),
            auth.env_id,
            auth.account_id
        );
        let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("store returned {}", resp.status()));
        }
        resp.json().await.map_err(|e| e.to_string())
    }

    async fn list_mailboxes(
        &self,
        auth: &AccessAuth,
        pattern: &str,
    ) -> Result<Vec<String>, String> {
        let arr = self.store_mailboxes(auth).await?;
        let mut lines = Vec::new();
        let empty: Vec<serde_json::Value> = Vec::new();
        for m in arr.as_array().unwrap_or(&empty) {
            let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() || !pattern_match(pattern, name) {
                continue;
            }
            let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("");
            let attrs: Vec<&str> = match role {
                "trash" => vec!["\\Trash"],
                "junk" => vec!["\\Junk"],
                "drafts" => vec!["\\Drafts"],
                "sent" => vec!["\\Sent"],
                "archive" => vec!["\\Archive"],
                _ => vec![],
            };
            lines.push(email8::imap_proto::list_line(&attrs, "/", name));
        }
        Ok(lines)
    }

    async fn select_mailbox(
        &mut self,
        auth: &AccessAuth,
        mailbox: &str,
    ) -> Result<Vec<String>, String> {
        let arr = self.store_mailboxes(auth).await?;
        let target = mailbox.trim_matches('"');
        let empty: Vec<serde_json::Value> = Vec::new();
        let mb = arr
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .find(|m| {
                m.get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n.eq_ignore_ascii_case(target))
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("mailbox {target} not found"))?
            .clone();
        let mailbox_id: Uuid = mb
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(Uuid::nil);
        let uidvalidity = mb.get("uid_validity").and_then(|v| v.as_i64()).unwrap_or(1);
        let uid_next = mb.get("uid_next").and_then(|v| v.as_i64()).unwrap_or(1);
        // Load the message listing (id, uid) from the Store.
        self.listing = self.store_mailbox_listing(auth, mailbox_id).await;
        let exists = self.listing.len() as i64;
        self.selected = Some((mailbox_id, uidvalidity, uid_next));
        Ok(vec![email8::imap_proto::select_ok(
            uidvalidity,
            uid_next,
            exists,
        )])
    }

    async fn status_mailbox(
        &self,
        auth: &AccessAuth,
        mailbox: &str,
        items: &[email8::imap_proto::StatusItem],
    ) -> Result<String, String> {
        use email8::imap_proto::StatusItem;
        let arr = self.store_mailboxes(auth).await?;
        let target = mailbox.trim_matches('"');
        let empty: Vec<serde_json::Value> = Vec::new();
        let mb = arr
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .find(|m| {
                m.get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n.eq_ignore_ascii_case(target))
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("mailbox {target} not found"))?
            .clone();
        let id: Uuid = mb
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(Uuid::nil);
        let mut out: Vec<(&str, i64)> = Vec::new();
        for item in items {
            match item {
                StatusItem::Messages => {
                    out.push((
                        "MESSAGES",
                        mb.get("total").and_then(|v| v.as_i64()).unwrap_or(0),
                    ));
                }
                StatusItem::UidNext => {
                    out.push((
                        "UIDNEXT",
                        mb.get("uid_next").and_then(|v| v.as_i64()).unwrap_or(1),
                    ));
                }
                StatusItem::UidValidity => {
                    out.push((
                        "UIDVALIDITY",
                        mb.get("uid_validity").and_then(|v| v.as_i64()).unwrap_or(1),
                    ));
                }
                StatusItem::Unseen => {
                    out.push((
                        "UNSEEN",
                        mb.get("unread").and_then(|v| v.as_i64()).unwrap_or(0),
                    ));
                }
                StatusItem::Deleted => {
                    out.push((
                        "DELETED",
                        mb.get("deleted").and_then(|v| v.as_i64()).unwrap_or(0),
                    ));
                }
                StatusItem::Size => {
                    out.push(("SIZE", mb.get("size").and_then(|v| v.as_i64()).unwrap_or(0)));
                }
                // RECENT is deprecated in IMAP4rev2; HIGHESTMODSEQ
                // arrives with CONDSTORE (Epic 4.1).
                StatusItem::Recent | StatusItem::HighestModSeq => {}
            }
        }
        Ok(email8::imap_proto::status_line(id, &out))
    }

    async fn write_raw(&mut self, s: &str) -> std::io::Result<()> {
        self.stream.write_all(s.as_bytes()).await
    }

    // ── Op helpers over the Store data API ─────────────────────────────

    /// The message listing of a mailbox: (email_id, imap_uid).
    /// Raw message bytes via the Store JMAP download endpoint.
    async fn fetch_raw_blob(&self, auth: &AccessAuth, blob_hash: &str) -> Result<Vec<u8>, String> {
        if blob_hash.is_empty() {
            return Ok(Vec::new());
        }
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/jmap/download/{}/{blob_hash}/raw.eml",
            self.config.store_url.trim_end_matches('/'),
            auth.account_id
        );
        let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| e.to_string())
    }

    async fn store_mailbox_listing(&self, auth: &AccessAuth, mailbox_id: Uuid) -> Vec<(Uuid, i64)> {
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/mailbox/emails?env_id={}&account_id={}&mailbox_id={}",
            self.config.store_url.trim_end_matches('/'),
            auth.env_id,
            auth.account_id,
            mailbox_id
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
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolve a sequence set (message numbers or UIDs) → (seq, email_id,
    /// uid) triples against the current listing.
    fn resolve_sequence(&self, sequence: &SequenceSet, uid_mode: bool) -> Vec<(i64, Uuid, i64)> {
        let max = self.listing.len() as i64;
        self.listing
            .iter()
            .enumerate()
            .filter(|(idx, (_, uid))| {
                let value = if uid_mode { *uid } else { *idx as i64 + 1 };
                sequence.contains(value as u64, max.max(1) as u64)
            })
            .map(|(idx, (id, uid))| (idx as i64 + 1, *id, *uid))
            .collect()
    }

    /// FETCH — the items the wire protocol needs; the raw body arrives as
    /// a literal from the blob endpoint.
    async fn op_fetch(
        &self,
        auth: &AccessAuth,
        mailbox_id: Uuid,
        sequence: &SequenceSet,
        items: &[FetchItem],
        uid_mode: bool,
    ) -> Result<Vec<String>, String> {
        let _ = mailbox_id;
        let targets = self.resolve_sequence(sequence, uid_mode);
        let mut lines = Vec::new();
        let _ = items
            .iter()
            .any(|i| matches!(i, FetchItem::Body { .. } | FetchItem::Rfc822));
        for (seq, email_id, uid) in targets {
            // Metadata via the per-email endpoint.
            let client = crate::store_http::store_client().await;
            let url = format!(
                "{}/v1/internal/email/{}/{}/{email_id}",
                self.config.store_url.trim_end_matches('/'),
                auth.env_id,
                auth.account_id
            );
            let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
            let meta: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
            for item in items {
                match item {
                    FetchItem::Uid => {
                        lines.push(email8::imap_proto::fetch_item(seq, "UID", uid.to_string()));
                    }
                    FetchItem::Flags => {
                        let flags = meta
                            .get("keywords")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|k| {
                                        k.as_str().map(|s| format!("\\{}", title_case(s)))
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        lines.push(email8::imap_proto::fetch_item(seq, "FLAGS", &flags));
                    }
                    FetchItem::InternalDate => {
                        let date = meta
                            .get("received_at")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        lines.push(email8::imap_proto::fetch_item(seq, "INTERNALDATE", date));
                    }
                    FetchItem::Rfc822Size => {
                        let size = meta.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
                        lines.push(email8::imap_proto::fetch_item(
                            seq,
                            "RFC822.SIZE",
                            size.to_string(),
                        ));
                    }
                    FetchItem::Rfc822 => {
                        // RFC822 ≡ BODY[] — the full raw message.
                        let email_id = meta.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                        let blob = meta
                            .get("blob_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let raw = self.fetch_raw_blob(auth, blob).await.unwrap_or_default();
                        lines.push(email8::imap_proto::fetch_literal(seq, "RFC822", &raw));
                        let _ = email_id;
                    }
                    FetchItem::Body {
                        section,
                        partial: _,
                        peek: _,
                    } => {
                        // The raw blob lives in Storage; slice the requested
                        // section (HEADER.FIELDS list, HEADER, TEXT, full) out
                        // of it and frame it as a literal (RFC 9051 §4.1.2).
                        let blob = meta
                            .get("blob_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let raw = self.fetch_raw_blob(auth, &blob).await.unwrap_or_default();
                        let bytes: Vec<u8> = if section.is_empty() {
                            raw
                        } else if section.eq_ignore_ascii_case("HEADER") {
                            header_block(&raw)
                        } else if let Some(rest) = section.strip_prefix("HEADER.FIELDS") {
                            let wanted: Vec<String> = rest
                                .trim()
                                .trim_start_matches('(')
                                .trim_end_matches(')')
                                .split_whitespace()
                                .map(|f| f.trim_matches('"').to_ascii_lowercase())
                                .collect();
                            header_fields(&raw, &wanted)
                        } else {
                            // TEXT and unknown sections: the full raw for now.
                            raw
                        };
                        let item_name = if section.is_empty() {
                            "BODY[]"
                        } else {
                            "BODY[HEADER]"
                        };
                        lines.push(email8::imap_proto::fetch_literal(seq, item_name, &bytes));
                    }
                    FetchItem::Envelope => {
                        let env = format!(
                            "({} {})",
                            meta.get("subject")
                                .and_then(|v| v.as_str())
                                .unwrap_or("NIL"),
                            meta.get("message_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("NIL"),
                        );
                        lines.push(email8::imap_proto::fetch_item(seq, "ENVELOPE", &env));
                    }
                    _ => {}
                }
            }
        }
        Ok(lines)
    }

    /// STORE — flag updates (\Seen etc.) + \Deleted accumulation.
    async fn op_store(
        &mut self,
        auth: &AccessAuth,
        mailbox_id: Uuid,
        sequence: &SequenceSet,
        items: &[StoreItem],
        silent: bool,
        uid_mode: bool,
    ) -> Result<(), String> {
        let _ = mailbox_id;
        let targets = self.resolve_sequence(sequence, uid_mode);
        for (_, email_id, _) in &targets {
            for item in items {
                match item {
                    StoreItem::Flags(flags) | StoreItem::Add(flags) | StoreItem::Remove(flags) => {
                        // Translate to the keywords column via the
                        // internal endpoint (write path).
                        let client = crate::store_http::store_client().await;
                        let url = format!(
                            "{}/v1/internal/email/keywords",
                            self.config.store_url.trim_end_matches('/'),
                        );
                        let set = matches!(item, StoreItem::Add(_) | StoreItem::Flags(_));
                        let _ = client
                            .post(&url)
                            .json(&serde_json::json!({
                                "env_id": auth.env_id,
                                "account_id": auth.account_id,
                                "email_id": email_id,
                                "set": set,
                                "keywords": flags,
                            }))
                            .send()
                            .await;
                        // \Deleted accumulates into the expunge list.
                        if flags.contains("\\Deleted") && set {
                            if !self.pending_expunge.contains(email_id) {
                                self.pending_expunge.push(*email_id);
                            }
                        } else if flags.contains("\\Deleted") && !set {
                            self.pending_expunge.retain(|id| id != email_id);
                        }
                    }
                }
            }
        }
        if !silent {
            // Unolicited FETCH FLAGS responses would repeat the stored
            // state; the client opted into them.
        }
        Ok(())
    }

    /// SEARCH — the basic criteria set against the listing metadata.
    async fn op_search(
        &self,
        auth: &AccessAuth,
        _mailbox_id: Uuid,
        criteria: &email8::imap_proto::SearchCriteria,
    ) -> Result<Vec<i64>, String> {
        let mut hits = Vec::new();
        for (idx, (email_id, _)) in self.listing.iter().enumerate() {
            let client = crate::store_http::store_client().await;
            let url = format!(
                "{}/v1/internal/email/{}/{}/{email_id}",
                self.config.store_url.trim_end_matches('/'),
                auth.env_id,
                auth.account_id
            );
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let Ok(meta) = resp.json::<serde_json::Value>().await else {
                continue;
            };
            let keywords = meta
                .get("keywords")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let subject = meta
                .get("subject")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let from = meta
                .get("metadata")
                .and_then(|m| m.get("from"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let mut hit = true;
            if let Some(seen) = criteria.seen {
                hit &= keywords.iter().any(|k| k.eq_ignore_ascii_case("seen")) == seen;
            }
            if let Some(flagged) = criteria.flagged {
                hit &= keywords.iter().any(|k| k.eq_ignore_ascii_case("flagged")) == flagged;
            }
            if let Some(deleted) = criteria.deleted {
                hit &= keywords.iter().any(|k| k.eq_ignore_ascii_case("deleted")) == deleted;
            }
            if let Some(answ) = criteria.answered {
                hit &= keywords.iter().any(|k| k.eq_ignore_ascii_case("answered")) == answ;
            }
            if let Some(draft) = criteria.draft {
                hit &= keywords.iter().any(|k| k.eq_ignore_ascii_case("draft")) == draft;
            }
            if let Some(text) = &criteria.subject {
                hit &= subject.contains(&text.to_lowercase());
            }
            if let Some(text) = &criteria.from {
                hit &= from.contains(&text.to_lowercase());
            }
            if hit {
                hits.push(idx as i64 + 1);
            }
        }
        Ok(hits)
    }

    /// RFC 5256 SORT — search filter + sort keys over the selected
    /// mailbox. Returns (sequence, uid) pairs in sorted order.
    async fn op_sort(
        &self,
        auth: &AccessAuth,
        mailbox_id: Uuid,
        keys: &[String],
        criteria: &email8::imap_proto::SearchCriteria,
    ) -> Result<Vec<(i64, i64)>, String> {
        let candidates = self.op_search(auth, mailbox_id, criteria).await?;
        // Gather (seq, uid, subject, from, received) for each hit.
        let mut rows: Vec<(i64, i64, String, String, String)> = Vec::new();
        for seq in candidates {
            let Some((email_id, uid)) = self.listing.get((seq - 1) as usize).copied() else {
                continue;
            };
            let meta = self.fetch_email_meta(auth, email_id).await;
            let subject = meta
                .as_ref()
                .and_then(|m| m.get("subject").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_lowercase();
            let from = meta
                .as_ref()
                .and_then(|m| {
                    m.get("metadata")
                        .and_then(|d| d.get("from"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("")
                .to_lowercase();
            let received = meta
                .as_ref()
                .and_then(|m| m.get("received_at").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            rows.push((seq, uid, subject, from, received));
        }
        // Apply the sort keys in reverse order (last key is primary —
        // RFC 5256: SORT (DATE SUBJECT) sorts by subject, then date).
        for key in keys.iter().rev() {
            match key.as_str() {
                "SUBJECT" => rows.sort_by(|a, b| a.2.cmp(&b.2)),
                "FROM" => rows.sort_by(|a, b| a.3.cmp(&b.3)),
                "DATE" | "ARRIVAL" | "REVERSE" | "REVERSEDATE" => {
                    rows.sort_by(|a, b| a.4.cmp(&b.4))
                }
                // SIZE / CC / TO approximated by sequence (stable).
                _ => rows.sort_by_key(|a| a.0),
            }
        }
        Ok(rows
            .into_iter()
            .map(|(seq, uid, _, _, _)| (seq, uid))
            .collect())
    }

    /// RFC 5256 THREAD — group the search hits into threads. The
    /// REFERENCES algorithm groups by normalized subject (the Store's
    /// CheekyHash threading reuses normalized subject as its primary
    /// key, so subject grouping matches the server's thread identity);
    /// ORDEREDSUBJECT lists members in arrival order.
    async fn op_thread(
        &self,
        auth: &AccessAuth,
        mailbox_id: Uuid,
        algorithm: &str,
        criteria: &email8::imap_proto::SearchCriteria,
    ) -> Result<Vec<Vec<(i64, i64)>>, String> {
        let candidates = self.op_search(auth, mailbox_id, criteria).await?;
        let mut rows: Vec<(i64, i64, String, String)> = Vec::new();
        for seq in candidates {
            let Some((email_id, uid)) = self.listing.get((seq - 1) as usize).copied() else {
                continue;
            };
            let meta = self.fetch_email_meta(auth, email_id).await;
            let subject = meta
                .as_ref()
                .and_then(|m| m.get("subject").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let received = meta
                .as_ref()
                .and_then(|m| m.get("received_at").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            rows.push((seq, uid, subject, received));
        }
        if algorithm == "ORDEREDSUBJECT" {
            // One flat group in arrival order.
            rows.sort_by(|a, b| a.3.cmp(&b.3));
            return Ok(vec![rows.into_iter().map(|(s, u, _, _)| (s, u)).collect()]);
        }
        // REFERENCES: bucket by normalized subject (re:/fw: stripped).
        let mut buckets: std::collections::BTreeMap<String, Vec<(i64, i64, String)>> =
            Default::default();
        for (seq, uid, subject, received) in rows {
            let norm = email8::mail_core::normalize_subject(&subject);
            buckets.entry(norm).or_default().push((seq, uid, received));
        }
        let groups: Vec<Vec<(i64, i64)>> = buckets
            .into_values()
            .map(|mut members| {
                members.sort_by(|a, b| a.2.cmp(&b.2)); // arrival order within thread
                members.into_iter().map(|(s, u, _)| (s, u)).collect()
            })
            .collect();
        Ok(groups)
    }

    /// Fetch one email's metadata via the Store per-email endpoint
    /// (shared by SEARCH/SORT/THREAD).
    async fn fetch_email_meta(
        &self,
        auth: &AccessAuth,
        email_id: Uuid,
    ) -> Option<serde_json::Value> {
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/email/{}/{}/{email_id}",
            self.config.store_url.trim_end_matches('/'),
            auth.env_id,
            auth.account_id
        );
        let resp = client.get(&url).send().await.ok()?;
        resp.json::<serde_json::Value>().await.ok()
    }

    /// COPY/MOVE — the membership add (COPY) + optional destroy (MOVE).
    async fn op_copy(
        &self,
        auth: &AccessAuth,
        src_mailbox: Uuid,
        sequence: &SequenceSet,
        dest_mailbox: &str,
        uid_mode: bool,
        is_move: bool,
    ) -> Result<(), String> {
        // Resolve the destination mailbox id.
        let arr = self.store_mailboxes(auth).await?;
        let target = dest_mailbox.trim_matches('"');
        let empty: Vec<serde_json::Value> = Vec::new();
        let dest_id = arr
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .find(|m| {
                m.get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n.eq_ignore_ascii_case(target))
                    .unwrap_or(false)
            })
            .and_then(|m| m.get("id"))
            .and_then(|v| v.as_i64())
            .ok_or_else(|| format!("mailbox {target} not found"))?;
        let targets = self.resolve_sequence(sequence, uid_mode);
        let ids: Vec<Uuid> = targets.iter().map(|(_, id, _)| *id).collect();
        // Membership add via the internal endpoint.
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/emails/copy",
            self.config.store_url.trim_end_matches('/')
        );
        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "env_id": auth.env_id,
                "account_id": auth.account_id,
                "dest_mailbox_id": dest_id,
                "email_ids": ids,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("copy returned {}", resp.status()));
        }
        if is_move {
            self.store_destroy_emails_pub(auth, src_mailbox, &ids)
                .await?;
        }
        Ok(())
    }

    /// APPEND — literal bytes were inlined by the receiver; the raw
    /// message is re-materialized from the command reconstruction.
    async fn op_append(&self, auth: &AccessAuth, mailbox: &str) -> Result<Option<i64>, String> {
        // Resolve the destination.
        let arr = self.store_mailboxes(auth).await?;
        let target = mailbox.trim_matches('"');
        let empty: Vec<serde_json::Value> = Vec::new();
        let dest_id = arr
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .find(|m| {
                m.get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n.eq_ignore_ascii_case(target))
                    .unwrap_or(false)
            })
            .and_then(|m| m.get("id"))
            .and_then(|v| v.as_i64())
            .ok_or_else(|| format!("mailbox {target} not found"))?;
        // The APPEND literal content was already inlined by the receiver
        // into `self.last_literal` — see `run()`'s LiteralContinuation
        // handling. This is stored by the session's append buffer.
        let raw = self
            .append_literal
            .as_ref()
            .ok_or("APPEND requires a {n} literal")?;
        // Blob store + ingest in one call (the store endpoint combines
        // them for the APPEND path).
        use base64::Engine;
        let raw_b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/ingest/append",
            self.config.store_url.trim_end_matches('/')
        );
        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "env_id": auth.env_id,
                "account_id": auth.account_id,
                "mailbox_id": dest_id,
                "raw_b64": raw_b64,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("append returned {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body.get("imap_uid").and_then(|v| v.as_i64()))
    }

    /// Destroy emails (EXPUNGE/CLOSE/MOVE) — the internal batch endpoint.
    async fn store_destroy_emails(
        &self,
        auth: &AccessAuth,
        mailbox_id: Uuid,
        ids: &[Uuid],
    ) -> Result<(), String> {
        self.store_destroy_emails_pub(auth, mailbox_id, ids).await
    }

    async fn store_destroy_emails_pub(
        &self,
        auth: &AccessAuth,
        mailbox_id: Uuid,
        ids: &[Uuid],
    ) -> Result<(), String> {
        let client = crate::store_http::store_client().await;
        let url = format!(
            "{}/v1/internal/emails/destroy",
            self.config.store_url.trim_end_matches('/')
        );
        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "env_id": auth.env_id,
                "account_id": auth.account_id,
                "mailbox_id": mailbox_id,
                "email_ids": ids,
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("destroy returned {}", resp.status()));
        }
        Ok(())
    }
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// IMAP LIST pattern matching: `*` matches everything, `%` matches one
/// level only (no `/` crossing), no wildcards = exact (case-insensitive).
fn pattern_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('%') {
        let pat = pattern.replace('%', "");
        return name
            .replace('/', "")
            .to_lowercase()
            .contains(&pat.to_lowercase());
    }
    name.eq_ignore_ascii_case(pattern)
}

/// The full header block of a raw RFC 5322 message (through the blank line).
fn header_block(raw: &[u8]) -> Vec<u8> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(raw.len());
    raw[..end].to_vec()
}

/// The requested header fields (case-insensitive) + the terminating blank
/// line — RFC 9051 §6.4.5 BODY[HEADER.FIELDS (<list>)].
fn header_fields(raw: &[u8], wanted: &[String]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let block = header_block(raw);
    let mut start = 0usize;
    for i in 0..=block.len() {
        if i == block.len() || (block[i] == b'\n' && i > 0 && block[i - 1] == b'\r') {
            let line = &block[start..i];
            start = i + 1;
            let name: Vec<u8> = line
                .split(|&b| b == b':')
                .next()
                .unwrap_or(&[])
                .to_ascii_lowercase();
            if wanted.iter().any(|w| name.starts_with(w.as_bytes())) {
                out.extend_from_slice(line);
            }
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}
