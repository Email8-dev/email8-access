-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Email8:Access
-- SPDX-License-Identifier: Apache-2.0

-- ── Local audit journal (AUDJOUR-1, design/sentin8-audit-journal-provisioning-design.md §2.1) ──
-- DBX migration v2: the local audit journal in THIS service's leaf schema,
-- the 15-column contract of `sentin8_audit::audit_journal_sql("access")`
-- (architecture-principles §6.8 — journal-first audit; the shell's boot
-- step 8c pusher drains unpushed rows to Sys `POST /v1/audit` and marks
-- them pushed on 2xx; a Sys outage only delays delivery).
--
-- Layout: the `access` leaf schema holds nothing today — this migration is
-- its first object. The shell's pusher SELECTs `FROM audit_journal`
-- UNQUALIFIED on the service's main pool, which resolves through the
-- role's search_path (`access, email8, public`).
CREATE SCHEMA IF NOT EXISTS access;
CREATE TABLE IF NOT EXISTS access.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_access_audit_journal_unpushed
    ON access.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE access.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON access.audit_journal;
CREATE POLICY audit_journal_dml ON access.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- Per-service grants: the role owns its leaf schema; the pusher's
-- SELECT/UPDATE (mark-pushed) runs on the service's main pool.
GRANT USAGE ON SCHEMA access TO email8_access_service;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA access TO email8_access_service;