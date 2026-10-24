# Email8:Access - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Email8:Access **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Email8:Access is the **classic mailbox protocol surface** of the Email
product line. It delivers:

- **Client reach without webmail** - Thunderbird, Apple Mail, Outlook,
  mobile mail clients, backup tools, and migration pipelines reach the
  mailboxes over the protocols they already speak: IMAP, POP3, and
  ManageSieve, plus CalDAV/CardDAV/WebDAV for calendar and contact
  synchronization.
- **One mailbox, many clients** - the same underlying mailbox data is
  projected consistently across protocols; a message filed by a JMAP
  client is visible to an IMAP client seconds later.
- **Server-side filtering** - users manage their own Sieve scripts from
  any client, so rules follow the account rather than the device.
- **Zero data at risk at this layer** - Access holds no mail data of its
  own; every byte and metadata row lives in Email8:Store, so adding or
  replacing protocol frontends never touches storage.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | IMAP sessions | Full IMAP4rev2/rev1 reading, flagging, searching, sorting, threading, copying, moving, idling over the user's mailboxes |
| 2 | POP3 sessions | Lightweight download access to the INBOX projection (UIDL, TOP, UID-based delete) |
| 3 | ManageSieve | Script listing, upload, compile-check, activation, deletion, rename - RFC 5804 store for server-side filters |
| 4 | CalDAV | Calendar collection browsing, query reports with time-range filters, event create/update/delete, sync-collection |
| 5 | CardDAV | Address book browsing, contact queries, card CRUD, sync-collection |
| 6 | WebDAV files | File node browsing and content transfer for the account's file space |
| 7 | Access control | Shared-mailbox ACL rights surfaced per protocol (grant/revoke/effective rights via the Store data API) |
| 8 | Fleet health | Health endpoint + listener advertisement for the Gate's port passthrough |
| 9 | Admin console | Remote admin pages (IMAP, Sieve) rendered in the platform dashboard |
| 10 | Telemetry | Service telemetry frames on the platform property |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Mail data, mailboxes, threads, calendar/contact/file storage | Email8:Store (Access is stateless over its data API) |
| Port ownership for clients (25/465/587/143/993/...) | Email8:Gate (Access binds OS-ephemeral; the Gate fronts it) |
| User identity, passwords, token issuance | Sentin8:Auth (Access only verifies presented credentials) |
| Authorization decisions | Shield policy engine (scope-based, roles resolved live) |
| Message bytes (blobs) | Sentin8:Storage (referenced through Store) |
| Submission / outgoing mail | Email8:Mta (JMAP EmailSubmission proxies there) |
| Web UI for mail | Email8:Webmail (over JMAP, not over Access) |
| Event transport, scheduling, storage infra | Sentin8:Bus, Sentin8:Cron, Sentin8:Storage (platform) |

## 3. Business Capabilities

### 3.1 IMAP mailbox access

| Capability | Business rule |
|---|---|
| Authenticate | Credentials are platform tokens (XOAUTH2/OAUTHBEARER); a session exists only for a verified account mapped in the store's principal registry |
| List/select mailboxes | Clients see the account's folder tree including the six bootstrap special-use folders (INBOX, Trash, Junk, Drafts, Sent, Archive) |
| Read messages | FETCH covers envelope, body structure, text, binary parts, size, flags, internal date |
| Modify state | STORE with keywords/flags (including junk keywords that feed the spam-learning pipeline via Store), EXPUNGE, CLOSE, UNSELECT |
| Organize | APPEND (incl. MULTIAPPEND), COPY, MOVE between mailboxes with per-mailbox UIDs preserved |
| Find messages | SEARCH, ESEARCH, SORT (RFC 5256), THREAD, SEARCHRES; filtering by flags, dates, addresses, text |
| Change tracking | CONDSTORE/QRESYNC via Store's changelog: incremental sync without re-downloading |
| Long-poll | IDLE holds a session open; a mailbox change ends it per protocol semantics |
| Session limit | 30-minute idle timeout per session |

### 3.2 POP3 inbox download

| Capability | Business rule |
|---|---|
| Authenticate | USER/PASS with the PASS field carrying the platform token |
| List/download | INBOX-only projection; message listing with sizes, TOP retrieval of headers+lines |
| Delete on quit | DELE marks are applied as a batch on QUIT; RSET reverts them |
| Stable identity | UIDL = `{uid_validity}{uid}` so clients deduplicate downloads |
| Interop guards | CAPA advertises STLS/UIDL/TOP/USER/PIPELINING/UTF8; APOP is rejected |

### 3.3 Sieve script management

| Capability | Business rule |
|---|---|
| List scripts | Scripts per account with active-script indication |
| Upload/validate | PUTSCRIPT compiles the script server-side; a malformed script is rejected before it can misroute mail |
| Activate | One active script per account at a time |
| Maintain | GETSCRIPT, DELETESCRIPT, RENAMESCRIPT, CHECKSCRIPT, HAVESPACE (permissive quota) |

### 3.4 Calendar, contacts, and files (DAV)

| Capability | Business rule |
|---|---|
| Discover | OPTIONS advertises DAV class 1/2/3, access-control, calendar-access, addressbook |
| Browse | PROPFIND (Depth 0/1) multistatus listings; MKCOL/MKCALENDAR create collections |
| Query | REPORT: calendar-query (time-range), addressbook-query, sync-collection (incremental sync) |
| Edit | GET/PUT/DELETE on resources; PROPPATCH-lite property updates |
| Lock | LOCK/UNLOCK (class-2) so two clients cannot clobber one resource |
| Share | ACL method reads effective rights |

### 3.5 Security and tenancy

| Capability | Business rule |
|---|---|
| Token-first auth | XOAUTH2/OAUTHBEARER; no password path is implemented |
| Scope gating | Every protocol action maps to an `email8:mail:read`/`email8:mail:write` policy decision (Shield, roles resolved live) - token expiry/revocation takes effect on the next command |
| Tenant isolation | Every store call is tenant-stamped; account binding is sub→principal and is re-established per credential verification |
| Audit | Authentication outcomes, protocol mutations and errors land in the service audit journal, pushed to the platform audit API |

## 4. Business Events (Outbound)

Email8:Access publishes **no domain events**: it mutates nothing
directly - all effects (filing, keyword changes, deletions) happen in
Email8:Store, which owns the event stream. Access contributes audit
journal rows (drained to the platform audit API) and telemetry frames.

**Inbound (consumed):** none. The Shield hot-reload consumer rides the
service's dedicated `-policy` workload; there is no provisioning or
domain consumer at this layer.

| Channel | Content |
|---|---|
| Audit journal → Sentin8:Sys `POST /v1/audit` | Auth failures, scope refusals, protocol mutations (per AUDJOUR contract) |
| Telemetry → platform stat property `access` | Session/protocol counters (hourly frames) |

## 5. Business Rules & Invariants

1. Access is **stateless with respect to mail data**: the only table it
   owns is its audit journal. Loss or upgrade of Access never endangers
   mailbox content.
2. A client action can never exceed the calling token's scopes: read
   scopes cannot delete, and an expired/revoked token ends access at the
   next command.
3. One account is always bound per session: after authentication, every
   request is scoped to that account's data only - cross-account reads
   are structurally impossible from the protocol layer.
4. UID stability: per-mailbox UIDs and UIDVALIDITY survive because UID
   assignment and changelog entries happen once, in Store - never
   re-derived per protocol.
5. Junk-flagging from any protocol feeds the same spam-learning pipeline
   (keywords set through Store insert training samples).
6. Sieve scripts are compile-validated before activation; a broken
   script cannot silently reroute production mail.
7. The Gate owns the well-known ports; Access listeners bind
   OS-ephemeral and advertise themselves in the fleet registry, so
   rotating instances never breaks client connectivity.
8. Every authenticated mutation is audited; the platform audit record is
   the business trail of who did what to whose mailbox.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Email8:Access |
|---|---|
| End user with a desktop/mobile client | Sets up Thunderbird/Apple Mail/Outlook over IMAP; reads, files, flags, searches mail |
| Security-conscious user | Uses POP3 download to a local archive; deletes on server after download |
| Power user | Edits Sieve rules (vacation, filing, redirects) that run server-side for all clients |
| Calendar/contact user | Syncs calendar events and contacts over CalDAV/CardDAV from phone/desktop clients |
| Migration operator | Copies mailbox content in/out via IMAP APPEND and UID-based tooling |
| Email administrator | Watches the IMAP/Sieve admin pages in the platform dashboard; manages shared mailbox ACLs |
| Platform operator | Relies on health + telemetry for fleet supervision |

## 7. KPIs / Success Criteria

| Category | Target |
|---|---|
| Protocol correctness | Thunderbird/Apple Mail/Outlook interop without protocol-level workarounds; capability sets complete for the advertised commands |
| Latency | Sub-second response for typical LIST/FETCH/SEARCH on normal mailboxes |
| Consistency | A JMAP-side change is visible to IMAP clients within one changelog refresh (~seconds) |
| Security | Zero password storage, zero bearer tokens persisted; 100% of mutations authorized per request |
| Availability | Gate-passed ports stay live across Access rolling upgrades (ephemeral binds + registry refresh) |
| Auditability | Every auth failure and mutation appears in the platform audit stream |

## 8. Dependencies & Reliance on Other Services

| Relied on | For |
|---|---|
| Email8:Store | All mailbox/message/calendar/contact/sieve data reads and writes (internal data API) |
| Sentin8:Auth | Credential verification (token verify, principal lookup) |
| Shield (Sentin8:Policy) | Per-request authorization decisions |
| Email8:Gate | Client-facing well-known ports (IMAP 143/993, POP3 110/995, Sieve 4190) |
| Sentin8:Storage | Blob bytes fetched transitively via Store |
| Sentin8:Sys | Audit journal drain |
| Sentin8:Bus | Policy-definition hot reload (workload consumer) |
| Sentin8:Stat | Telemetry property + metric ingest |

## 9. Acceptance Criteria

1. An IMAP client can complete authenticate → list → select → fetch →
   store → expunge against real Store data with correct untagged
   responses.
2. A POP3 client can download exactly the INBOX projection and delete
   via UIDL-stable identities.
3. A Sieve client can round-trip list/put/activate/get/delete scripts.
4. A CalDAV client can discover calendars, run time-range query reports,
   and create/update/delete events; a CardDAV client likewise for
   contacts; sync-collection returns incremental changes.
5. Protocol access with an expired or out-of-scope token is refused with
   the mapped error, audited, and never falls back to partial data.
6. No mail data is stored on Access at any point; a cold Access node
   serves clients after only listener re-advertisement.
7. `make build`, `make test`, `make lint` pass; the OpenAPI spec matches
   the implemented routes (drift test).

## 10. Open Business Questions

- Offline/undocumented IMAP extensions some niche clients expect
  (e.g. legacy vendor quirks) - extend the capability set as real
  client demand appears.
- Per-protocol connection limits as a tenant-visible quota (currently a
  service-level setting only).

---

**Architecture & Design:** email8:access and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).