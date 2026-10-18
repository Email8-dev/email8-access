// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Email8:Access.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_delete_attribute,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_test_set,
        crate::server::health,
        crate::dav::dispatch,
        crate::dav::dispatch_root,
    ),
    components(schemas(
        sentin8::shield::admin::PutPolicySetBody,
        sentin8::shield::admin::TestPolicySetBody,
        sentin8::shield::admin::PolicyModeBody,
        sentin8::shield::admin::PutRelationBody,
        sentin8::shield::admin::DeleteRelationQuery,
        sentin8::shield::admin::RelationCheckQuery,
        sentin8::shield::admin::PutAttributeBody,
        sentin8::shield::admin::ListAttributesQuery,
        sentin8::shield::admin::DeleteAttributeQuery,
    )),
    security(),
    tags(
        (name = "email8-access", description = "Sentin8 Email8:Access — IMAP, POP3, ManageSieve, DAV protocol services"),
        (name = "dav", description = "RFC 4918 WebDAV surface (CalDAV/CardDAV)"),
        (name = "policy", description = "Shield policy admin (generic-handler surface)"),
        (name = "meta", description = "Liveness/service metadata"),
    ),
)]
pub struct AccessOpenApi;
