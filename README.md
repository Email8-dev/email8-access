# Sentin8 Email8:Access - Mailbox Protocol Services

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://email8.dev/docs/services/access)
[![Website](https://img.shields.io/badge/website-email8.dev-1a73e8.svg)](https://email8.dev)

## 1. Summary

Email8:Access serves the mailbox access protocols: IMAP (with full
CAPABILITY handling), POP3, ManageSieve, and the CalDAV/CardDAV/
WebDAV collaboration endpoints. It reads mail data through the
Store's data API (certificate-authenticated) and exposes the authenticated
user-plane protocols over the Gate's listeners.

## 2. Architecture

```mermaid
graph TD
    GATE[Email8:Gate] --> ACCESS[Access<br/>IMAP/POP3/Sieve/DAV]
    ACCESS -- M2M data API --> STORE[Email8:Store]
    ACCESS -- auth session verify --> AUTH[Sentin8:Auth]
```

## 3. Key Traits

- Full IMAP session state machine (protocol crates live in
  `email8-sdk` - `imap_proto`, `sieve`, `dav_proto`, `ical`,
  `vcard`).
- M2M: certificate identity (CERTFREE-4V) - the Access workload cert
  presents in the TLS handshake; no bearer token on the Store data API.
- Audit journal (architecture-principles §6.8): the
  `access.audit_journal` leaf-schema table (migration v2 - the 15-column
  `sentin8_audit::audit_journal_sql` contract, the access leaf schema's
  first object) is drained to Sys `POST /v1/audit` by the shell's
  boot-8c pusher, presenting the `access-audit` workload certificate
  (`sentin8:sys:audit:write`).
- Zero mailbox storage at this layer - Store owns persistence.

See the vertical group docs (`email8/README.md`) for the plane
overview.

---

**Architecture & Design:** email8:access and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
