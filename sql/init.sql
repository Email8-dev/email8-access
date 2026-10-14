-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
-- SPDX-License-Identifier: Apache-2.0

-- Email8:Access schema bootstrap.
--
-- Access owns NO tables (single-writer rule: all mail data lives in
-- Email8:Store; queue data in Email8:Mta). This file exists only so the
-- platform `vertical init` SQL stage finds a migration for this service
-- and so the service's PG role is registered. Role grants are applied
-- by the platform bootstrap (design §2.1).

-- The email8_access_service role is created by Email8:Store's init.sql
-- (roles for all four email8 services are declared there); nothing to
-- do here.
SELECT 1;