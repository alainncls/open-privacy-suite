-- 056_rbac_audit_log_hash_chain.sql
-- RD-858: extend the audit hash chain (currently access_logs only, migration
-- 017) to cover rbac_audit_log. Admin actions on RBAC tables (groups,
-- grants, memberships, contract claim, etc.) are exactly the records SOC 2
-- CC7 / ISO 27001 auditors ask about under "change management evidence",
-- and pre-fix any actor with DB write access could rewrite the table
-- silently — there was no cryptographic linking of rows.
--
-- This migration is additive only (expand-only policy). The new column is
-- nullable so historical rows (created before this migration ran) stay
-- valid; new writes via CreateAuditLog populate it. The verifier (see
-- internal/audit/verifier.go) flags NULL entries on rows written after
-- the writer change shipped, which is what we want — those represent
-- either tampering or a process crash that the writer fix to single-
-- statement INSERT (RD-858 short-term tier item) is meant to prevent.
--
-- Chain seeding follows the same pattern as the access_logs chain:
--   1. Latest non-NULL entry_hash row.
--   2. Otherwise audit_chain_anchor (migration 042) — chain_name will be
--      'rbac_audit_log' once that chain has its first prune cut.
--   3. Otherwise the empty string (fresh chain).
--
-- The hash-format version is intentionally separate from the access_logs
-- format (which is "v2" at the time of this migration). rbac_audit_log
-- starts at v1; future format bumps (e.g. when more fields are added)
-- increment independently.

ALTER TABLE rbac_audit_log
    ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(128),
    ADD COLUMN IF NOT EXISTS hash_format_version SMALLINT NOT NULL DEFAULT 1;

COMMENT ON COLUMN rbac_audit_log.entry_hash IS
    'SHA-256(prev_entry_hash || canonical_row_content) hex. NULL for rows written before RD-858; verifier flags as integrity gap.';

COMMENT ON COLUMN rbac_audit_log.hash_format_version IS
    'Hash content schema version. The verifier picks the matching content builder by this column; new versions must be additive (never rewrite past formats).';
