// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Email8:Access.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    security(),
    tags(
        (name = "email8-access", description = "Sentin8 Email8:Access — IMAP, POP3, ManageSieve, DAV protocol services"),
    ),
)]
pub struct AccessOpenApi;
