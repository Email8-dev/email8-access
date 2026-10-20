// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Email8:Access.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, ErrorCode, M2mGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, SqlMigration,
};
#[cfg(not(test))]
use utoipa::OpenApi;

/// The Shield text of the declared scope-mirror set - public so the
/// policy wiring tests (POLICY-7) assert against the REAL seed.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:mail:read\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:mail:write\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:mail:write\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:mail:read\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:mail:receive\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:submission:send\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Enforced (decision 2026-09-07): step 5 is the
/// only gate; shadow is the emergency one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for email8:access over the LIVE effective scope set (policy design §3.1d). Enforced (decision 2026-09-07) - step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by this
/// service today; env admins author their own graph (delegate /
/// shared-mailbox edges) via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

/// M2M workload declarations (CERTFREE-4V): the `email8:access` workload
/// row drives `vertical enroll`'s Valkey ACL-user provisioning (the CN
/// `m2m-email8:access` maps to the ACL user of the same name - group
/// DESIGN.md §3.1) and carries the scopes Store's internal-data-API gate
/// checks for the IMAP/POP3/Sieve session flows.
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "email8:access",
        scopes: &[
            "email8:mail:read",
            "email8:mail:write",
            "email8:mail:receive",
        ],
    },
    M2mGrant {
        // Shield hot-reload consumer (policy crate `policy_bus_client`, full
        // colon identity - BUSPOLICY-1: the boot-minted cert is authorized by
        // the enroll-published registry map; without this declared row every
        // policy SSE connect 401s "workload is not enrolled".
        workload: "email8:access-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        // Audit-journal pusher's sys-ingest scope (AUDJOUR-1): the shell's
        // boot-8c pusher presents the `access-audit` certificate to Sys
        // `POST /v1/audit` - this grant row is what makes the workload
        // enrollable (the BUSPOLICY-1 class: an undeclared cert mints but
        // can never be authorized).
        workload: "access-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
];

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "email8:mail:read,email8:mail:write",
    role: "email8_access_service",
    bypass_rls: false,
    database: "email8",
    cross_schema_grants: &[],
}];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:imap",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:pop3",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:sieve",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:dav",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "email8:access:admin",
        scope: "email8:access:policy:read",
    },
    AdminScope::Typed {
        role: "email8:access:admin",
        scope: "email8:access:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "Email8StoreUnreachable",
        error_code: "email8_store_unreachable",
        status_code: 502,
    },
    ErrorCode {
        enum_name: "Email8InvalidToken",
        error_code: "email8_invalid_token",
        status_code: 401,
    },
    ErrorCode {
        enum_name: "Email8InsufficientScopes",
        error_code: "email8_insufficient_scopes",
        status_code: 403,
    },
    ErrorCode {
        enum_name: "Email8MailboxNotFound",
        error_code: "email8_mailbox_not_found",
        status_code: 404,
    },
    ErrorCode {
        enum_name: "Email8SieveScriptNotFound",
        error_code: "email8_sieve_script_not_found",
        status_code: 404,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "imap",
        label: "IMAP Sessions",
        ui_endpoint: "/v1/admin/ui/imap",
        data_endpoint: "/v1/admin/imap",
        icon: "0xe873",
    },
    AdminUiPage {
        route: "sieve",
        label: "Sieve Scripts",
        ui_endpoint: "/v1/admin/ui/sieve",
        data_endpoint: "/v1/admin/sieve",
        icon: "0xe0b9",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// AUDJOUR-1 migration v2: the local audit journal in the `access` leaf
/// schema (sql/audit.sql) - the 15-column contract of
/// `sentin8_audit::audit_journal_sql` (design/sentin8-audit-journal-
/// provisioning-design.md §2.1). The shell's boot-8c pusher drains it
/// to Sys `POST /v1/audit`. The `access` leaf schema is created by the
/// file itself (it holds nothing else today).
const SQL_2_AUDIT: &str = include_str!("../sql/audit.sql");

fn openapi_spec() -> serde_json::Value {
    // Portable stub when #[path]-included from tests (POLICY-7): the real
    // derive lives in the crate's openapi module, which tests don't link.
    #[cfg(not(test))]
    {
        serde_json::to_value(crate::openapi::AccessOpenApi::openapi())
            .unwrap_or(serde_json::Value::Null)
    }
    #[cfg(test)]
    return serde_json::Value::Null;
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "email8:access",
        subdomain: "email8-access",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Mail Access",
            icon: "0xe0e1",
            service_flag: "email8",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![
            SqlMigration {
                version: 1,
                name: "init",
                sql: SQL_1_INIT,
            },
            SqlMigration {
                version: 2,
                name: "audit",
                sql: SQL_2_AUDIT,
            },
        ],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
