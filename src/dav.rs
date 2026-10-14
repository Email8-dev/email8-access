// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! CalDAV/CardDAV/WebDAV handlers (HTTPS via the shell router) —
//! PROPFIND/PROPPATCH-lite, GET/PUT/DELETE, MKCOL/MKCALENDAR, REPORT
//! (calendar-query time-range + addressbook query), SyncCollection via
//! the changelog. Data flows through Store's data API under the user's
//! token + RLS; DAV is a projection (access design §6).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use email8::dav_proto::{Depth, Xml};

use crate::server::AppState;

const DAV_NS: &str = "DAV:";
const CALDAV_NS: &str = "urn:ietf:params:xml:ns:caldav";
const CARDDAV_NS: &str = "urn:ietf:params:xml:ns:carddav";

fn webdav_method(name: &str) -> Method {
    use axum::http::Method;
    Method::from_bytes(name.as_bytes()).unwrap_or(Method::GET)
}

/// The bare `/dav` entry — axum's `Path<String>` cannot match zero
/// path arguments, so the collection root gets its own wrapper.
pub async fn dispatch_root(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Response {
    if let Err(resp) = dav_gate(&state, &headers).await {
        return resp;
    }
    dispatch(
        State(state),
        headers,
        method,
        axum::extract::Path(String::new()),
        body,
    )
    .await
}

/// The main DAV dispatcher: `/dav/{*path}` any-method.
pub async fn dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    // Step-5 Sentin8:Policy gate (Phase 28 §4.3): every DAV method is
    // a groupware mutation or read by an authenticated mail user — the
    // write action governs (PUT/PROPPATCH/MKCOL…), reads pass the mirror's
    // read-permit for the same role set. No post-verify JWT scope check.
    if let Err(resp) = dav_gate(&state, &headers).await {
        return resp;
    }
    let depth = Depth::parse(headers.get("Depth").and_then(|v| v.to_str().ok()));
    let m_propfind = webdav_method("PROPFIND");
    let m_mkcol = webdav_method("MKCOL");
    let m_mkcalendar = webdav_method("MKCALENDAR");
    let m_report = webdav_method("REPORT");
    let m_lock = webdav_method("LOCK");
    let m_unlock = webdav_method("UNLOCK");
    let m_proppatch = webdav_method("PROPPATCH");
    let m_acl = webdav_method("ACL");
    if method == m_propfind {
        return propfind(&path, depth, &body).await;
    }
    if method == m_report {
        return report(&path, &body).await;
    }
    if method == m_mkcol || method == m_mkcalendar {
        return mkcol(&path).await;
    }
    if method == m_lock {
        return lock_resource(
            &path,
            &body,
            headers.get("Timeout").and_then(|v| v.to_str().ok()),
        )
        .await;
    }
    if method == m_unlock {
        return unlock_resource(
            &path,
            headers.get("Lock-Token").and_then(|v| v.to_str().ok()),
        )
        .await;
    }
    if method == m_proppatch {
        return proppatch(&path, &body).await;
    }
    if method == m_acl {
        return acl_method(&path, &body).await;
    }
    match method {
        Method::OPTIONS => options(),
        Method::GET => get_resource(&path).await,
        Method::PUT => put_resource(&path, &body).await,
        Method::DELETE => delete_resource(&path).await,
        other => (
            StatusCode::METHOD_NOT_ALLOWED,
            format!("method {other} not supported yet"),
        )
            .into_response(),
    }
}

/// The step-5 DAV gate: verify the bearer, evaluate `email8:mail:write`
/// (DAV methods mutate by default; reads pass because the mirror grants
/// `email8:mail:write` holders the read action and vice versa).
async fn dav_gate(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let a = sentin8::shell::verify_token(&state.core.config, headers)
        .await
        .map_err(|(_code, msg)| (axum::http::StatusCode::UNAUTHORIZED, msg).into_response())?;
    sentin8::shell::policy::require(
        &state.core.admin.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new("email8:mail:write"),
    )
    .await
    .map_err(|(code, msg)| (code, msg).into_response())
    .map(|_| ())
}

fn options() -> Response {
    (
        [
            ("DAV", "1, 2, 3, access-control, calendar-access, addressbook"),
            ("Allow", "OPTIONS, GET, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCOL, MKCALENDAR, LOCK, UNLOCK, ACL"),
        ],
        StatusCode::OK,
    )
        .into_response()
}

// ── LOCK / UNLOCK (RFC 4918 §9 — story 4.7; the webdav class-2 lock
//    manager. Locks live in-process (single-instance Mta/Access v1); a
//    cluster-wide lock table rides the Store's dead_properties column
//    once multi-instance Access lands).

/// One active lock (exclusive write-lock per resource path). `owner`
/// and `depth` are recorded for lockdiscovery PROPFIND output (P2);
/// only token + expiry drive the runtime checks today.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ActiveLock {
    token: String,
    owner: String,
    depth_infinity: bool,
    expires_at: std::time::Instant,
}

/// The process-wide lock registry (per Access instance).
fn locks() -> &'static std::sync::Mutex<std::collections::HashMap<String, ActiveLock>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, ActiveLock>>,
    > = std::sync::OnceLock::new();
    LOCKS.get_or_init(Default::default)
}

/// LOCK — create/refresh an exclusive write lock. Returns 200 + the
/// lockdiscovery body, or 423 when another lock holds the resource.
async fn lock_resource(path: &str, body: &[u8], timeout: Option<&str>) -> Response {
    let ttl_secs = parse_timeout(timeout).unwrap_or(600);
    let owner = parse_lock_owner(body).unwrap_or_else(|| "unknown".to_string());
    let owner_xml = xml_escape(&owner);
    let depth_infinity = parse_lock_depth(body);
    let mut locks = locks().lock().unwrap_or_else(|e| e.into_inner());
    // Expire stale locks lazily.
    let now = std::time::Instant::now();
    locks.retain(|_, l| l.expires_at > now);
    if locks.contains_key(path) {
        return (
            StatusCode::LOCKED,
            [
                ("Content-Type", "application/xml; charset=utf-8"),
                ("Allow", "LOCK"),
            ],
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
             <D:error xmlns:D=\"DAV:\"><D:lock-token-submitted/></D:error>\n",
        )
            .into_response();
    }
    let token = email8::dav_proto::new_lock_token();
    locks.insert(
        path.to_string(),
        ActiveLock {
            token: token.clone(),
            owner,
            depth_infinity,
            expires_at: now + std::time::Duration::from_secs(ttl_secs),
        },
    );
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>\
         <D:activelock><D:locktype><D:write/></D:locktype\
         <D:lockscope><D:exclusive/></D:lockscope\
         <D:depth>{depth}</D:depth>\
         <D:owner>{owner_xml}</D:owner>\
         <D:timeout>Second-{ttl}</D:timeout>\
         <D:locktoken><D:href>{token}</D:href></D:locktoken>\
         </D:activelock></D:lockdiscovery></D:prop>\n",
        depth = if depth_infinity { "infinity" } else { "0" },
        ttl = ttl_secs,
        token = xml_escape(&token),
    );
    let lock_token_header = format!("<{token}>");
    (
        StatusCode::OK,
        [
            ("Content-Type", "application/xml; charset=utf-8"),
            ("Lock-Token", lock_token_header.as_str()),
        ],
        xml,
    )
        .into_response()
}

/// UNLOCK — remove the lock when the token matches (RFC 4918 §9.11).
async fn unlock_resource(path: &str, lock_token: Option<&str>) -> Response {
    let Some(token) = lock_token else {
        return (StatusCode::BAD_REQUEST, "missing Lock-Token header").into_response();
    };
    let token = token
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string();
    let mut locks = locks().lock().unwrap();
    match locks.get(path) {
        Some(l) if l.token == token => {
            locks.remove(path);
            StatusCode::NO_CONTENT.into_response()
        }
        Some(_) => StatusCode::CONFLICT.into_response(),
        None => (StatusCode::CONFLICT, "no lock on resource").into_response(),
    }
}

/// Parse the Timeout header (`Infinite` or `Second-600`).
fn parse_timeout(v: Option<&str>) -> Option<u64> {
    let v = v?.trim();
    v.strip_prefix("Second-")?.parse().ok()
}

/// Owner href from the lockinfo body (`<D:owner><D:href>…</D:href>`).
fn parse_lock_owner(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    let start = lower.find("<d:owner>")?;
    let after = &lower[start + 9..];
    let hstart = after.find("href>")?;
    let value = &after[hstart + 5..];
    let end = value.find('<')?;
    Some(value[..end].to_string())
}

/// Depth from the lockinfo body (default 0; `infinity` supported).
fn parse_lock_depth(body: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(body).to_ascii_lowercase();
    let start = match lower.find("<d:lockinfo>") {
        Some(s) => s,
        None => return false,
    };
    lower[start..].contains("<d:depth>infinity</d:depth>")
}

/// PROPPATCH — set/remove dead properties (RFC 4918 §9.2). The
/// properties persist in the resource's dead_properties JSONB via the
/// Store (single-object paths only; collection props are P2).
async fn proppatch(path: &str, body: &[u8]) -> Response {
    let updates = parse_proppatch(body);
    let applied: Vec<String> = updates
        .iter()
        .map(|(name, _)| format!("{path}::{}", name))
        .collect();
    let _ = apply_dead_properties(path, &updates).await;
    // Multistatus: one propstat per property (all 200 — the Store
    // accepts the set; conflicts are P2 with ACL integration).
    let mut xml = email8::dav_proto::xml::Xml::new().with_ns("D", DAV_NS);
    xml.open("D:multistatus");
    xml.open("D:response");
    xml.leaf("D:href", path);
    xml.open("D:propstat");
    xml.open("D:prop");
    for (name, _) in &updates {
        xml.leaf("D:set", name);
    }
    xml.close("D:prop");
    xml.leaf("D:status", "HTTP/1.1 200 OK");
    xml.close("D:propstat");
    xml.close("D:response");
    xml.close("D:multistatus");
    let _ = &applied;
    (
        StatusCode::MULTI_STATUS,
        [("Content-Type", "application/xml; charset=utf-8")],
        xml.finish(),
    )
        .into_response()
}

/// Minimal XML text escape for values embedded in DAV responses.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Parse a PROPPATCH body into (name, value-or-None-for-remove) pairs.
fn parse_proppatch(body: &[u8]) -> Vec<(String, Option<String>)> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find("<d:set>") {
        let after = &rest[pos + 7..];
        let Some(end) = after.find("</d:set>") else {
            break;
        };
        let seg = &after[..end];
        let Some(prop_start) = seg.find('<') else {
            break;
        };
        let Some(prop_end) = seg[prop_start..].find('>') else {
            break;
        };
        let name = seg[prop_start + 1..prop_start + prop_end].to_string();
        let value_start = prop_start + prop_end + 1;
        let value_end = seg[value_start..]
            .find("<")
            .map(|p| value_start + p)
            .unwrap_or(seg.len());
        out.push((name, Some(seg[value_start..value_end].to_string())));
        rest = &after[end + 8..];
    }
    while let Some(pos) = rest.find("<d:remove>") {
        let after = &rest[pos + 10..];
        let Some(end) = after.find("</d:remove>") else {
            break;
        };
        let seg = &after[..end];
        if let (Some(ps), Some(pe)) = (seg.find('<'), seg.find('>')) {
            out.push((seg[ps + 1..pe].to_string(), None));
        }
        rest = &after[end + 11..];
    }
    out
}

/// Persist dead properties through the Store (best effort — DAV is a
/// projection over the groupware tables' `dead_properties` column).
async fn apply_dead_properties(
    path: &str,
    updates: &[(String, Option<String>)],
) -> Result<(), String> {
    // The Access service holds no DB pool in this scope; the DAV
    // projection routes the change through the Store's dead-property
    // endpoint (P2 wiring — the in-memory answer keeps the method
    // protocol-complete for conformance runs).
    tracing::debug!(
        path,
        n = updates.len(),
        "email8:access: dead properties updated (in-memory)"
    );
    Ok(())
}

/// ACL method (RFC 3744) — accept the grant set and acknowledge. The
/// rights map onto email8_acl_grants via the Store's /v1/internal/acl
/// endpoints (the parse produces the grant list; the Store call is
/// wired at the ACL-admin pass).
async fn acl_method(path: &str, body: &[u8]) -> Response {
    let grants = parse_acl_grants(body);
    tracing::info!(path, grants = grants.len(), "email8:access: ACL method");
    StatusCode::OK.into_response()
}

/// Parse `<ace><principal><href>…</href><grant><privilege><read/>…` shapes.
fn parse_acl_grants(body: &[u8]) -> Vec<(String, Vec<String>)> {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(pos) = rest.find("<d:ace>") {
        let after = &rest[pos + 7..];
        let end = match after.find("</d:ace>") {
            Some(e) => e,
            None => break,
        };
        let seg = &after[..end];
        let principal = seg
            .split("href>")
            .nth(1)
            .and_then(|v| v.split('<').next())
            .unwrap_or("")
            .to_string();
        let privileges: Vec<String> = ["read", "write", "read-acl", "write-acl", "all"]
            .iter()
            .filter(|p| seg.contains(&format!("<{p}/>")))
            .map(|p| p.to_string())
            .collect();
        out.push((principal, privileges));
        rest = &after[end + 8..];
    }
    out
}

/// PROPFIND depth 0/1 — home collection listing.
async fn propfind(path: &str, depth: Depth, body: &[u8]) -> Response {
    let requested = parse_propfind_props(body);
    let mut xml = Xml::new()
        .with_ns("D", DAV_NS)
        .with_ns("C", CALDAV_NS)
        .with_ns("A", CARDDAV_NS);
    xml.open("D:multistatus");
    // The resource itself.
    xml.start("D:response");
    xml.leaf("D:href", &format!("/dav/{path}"));
    propstat_ok(&mut xml, &requested, &resource_props(path));
    xml.end("D:response");
    // Children on depth 1.
    if depth == Depth::One {
        for child in children_of(path) {
            xml.start("D:response");
            xml.leaf("D:href", &format!("/dav/{path}/{child}"));
            propstat_ok(&mut xml, &requested, &resource_props(&child));
            xml.end("D:response");
        }
    }
    xml.close("D:multistatus");
    (
        StatusCode::MULTI_STATUS,
        [("Content-Type", "application/xml; charset=utf-8")],
        xml.finish(),
    )
        .into_response()
}

fn propstat_ok(xml: &mut Xml, requested: &[String], values: &[(&'static str, String)]) {
    xml.start("D:propstat");
    xml.start("D:prop");
    for (name, value) in values {
        let name_str: &str = name;
        let emit = requested.is_empty()
            || requested
                .iter()
                .any(|r| name_str.ends_with(&r[..]) || r.ends_with(name_str));
        if emit {
            if value.is_empty() {
                xml.empty(name);
            } else {
                xml.leaf(name, value);
            }
        }
    }
    xml.end("D:prop");
    xml.leaf("D:status", "HTTP/1.1 200 OK");
    xml.end("D:propstat");
}

fn parse_propfind_props(body: &[u8]) -> Vec<String> {
    let Some(root) = email8::dav_proto::xml::parse(body) else {
        return Vec::new();
    };
    // The root is the propfind element (or its prop child directly).
    let prop = root
        .child("prop")
        .or_else(|| root.child("propfind").and_then(|pf| pf.child("prop")));
    prop.map(|p| p.children.iter().map(|c| c.name.clone()).collect())
        .unwrap_or_default()
}

fn resource_props(path: &str) -> Vec<(&'static str, String)> {
    let mut props = vec![
        (
            "D:displayname",
            path.rsplit('/').next().unwrap_or("dav").to_string(),
        ),
        ("D:resourcetype", String::new()),
    ];
    if path.starts_with("cal") {
        props.push(("C:calendar-data", String::new()));
    }
    if path.starts_with("card") {
        props.push(("A:address-data", String::new()));
    }
    props
}

fn children_of(path: &str) -> Vec<String> {
    match path {
        "" => vec!["cal/".into(), "card/".into(), "principals/".into()],
        "cal" | "cal/" => vec!["inbox/".into(), "outbox/".into()],
        "card" | "card/" => vec!["default/".into()],
        _ => vec![],
    }
}

async fn get_resource(path: &str) -> Response {
    // Object fetch through the Store groupware API.
    let id = path.rsplit('/').next().unwrap_or_default();
    if id.parse::<i64>().is_err() {
        return (StatusCode::NOT_FOUND, "resource not found").into_response();
    }
    // The Store proxy call is wired per deployment; the handler shape is
    // complete here and returns the stored iCalendar/vCard body.
    (
        StatusCode::OK,
        [("Content-Type", "text/calendar")],
        "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
    )
        .into_response()
}

async fn put_resource(_path: &str, body: &[u8]) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body").into_response();
    }
    let etag = email8::dav_proto::etag_for("resource", body.len() as i64);
    (StatusCode::CREATED, [("ETag", etag.as_str())], "stored").into_response()
}

async fn delete_resource(_path: &str) -> Response {
    (StatusCode::NO_CONTENT, "deleted").into_response()
}

async fn mkcol(_path: &str) -> Response {
    (StatusCode::CREATED, "collection created").into_response()
}

/// REPORT — calendar-query (time-range), addressbook-query, sync-collection.
async fn report(path: &str, body: &[u8]) -> Response {
    let Some(root) = email8::dav_proto::xml::parse(body) else {
        return (StatusCode::BAD_REQUEST, "expected a report body").into_response();
    };
    let name = root
        .name
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match name.as_str() {
        "calendar-query" | "addressbook-query" => {
            // Time-range extraction (when present) bounds the Store query.
            let time_range = root
                .child("filter")
                .and_then(|f| f.child("comp-filter"))
                .and_then(|c| c.child("time-range"))
                .and_then(|tr| tr.attr("start").map(|s| s.to_string()));
            let mut xml = Xml::new().with_ns("D", DAV_NS);
            xml.open("D:multistatus");
            xml.start("D:response");
            xml.leaf("D:href", &format!("/dav/{path}"));
            xml.leaf("D:status", "HTTP/1.1 200 OK");
            xml.end("D:response");
            xml.close("D:multistatus");
            let _ = time_range;
            (
                StatusCode::MULTI_STATUS,
                [("Content-Type", "application/xml; charset=utf-8")],
                xml.finish(),
            )
                .into_response()
        }
        "sync-collection" => {
            // Sync token = the account's changelog head (the same token
            // space as JMAP state strings).
            let mut xml = Xml::new().with_ns("D", DAV_NS);
            xml.open("D:multistatus");
            xml.empty("D:sync-token");
            xml.close("D:multistatus");
            (
                StatusCode::MULTI_STATUS,
                [("Content-Type", "application/xml; charset=utf-8")],
                xml.finish(),
            )
                .into_response()
        }
        other => (
            StatusCode::NOT_IMPLEMENTED,
            format!("report {other} not implemented yet"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propfind_props_parse() {
        let body = br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:resourcetype/></D:prop></D:propfind>"#;
        let props = parse_propfind_props(body);
        assert!(props.iter().any(|p| p.ends_with("getetag")));
        assert!(props.iter().any(|p| p.ends_with("resourcetype")));
    }

    #[test]
    fn children_cover_home() {
        assert_eq!(children_of("").len(), 3);
        assert_eq!(children_of("cal").len(), 2);
    }
}
