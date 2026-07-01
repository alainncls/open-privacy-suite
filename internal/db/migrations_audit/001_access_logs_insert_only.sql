-- audit/001_access_logs_insert_only.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- Tightens the runtime app role (privacy_proxy_app) on access_logs in the
-- SEPARATE append-only audit database to INSERT + SELECT only. It REVOKEs the
-- UPDATE and DELETE that migration 058 kept on this table, and re-asserts the
-- GRANT SELECT, INSERT (+ the sequence USAGE the chained INSERT needs). This is
-- a REVOKE that TIGHTENS privilege — allowed under the expand-only policy
-- (expand-only forbids widening / destructive schema DDL; narrowing a grant is
-- a security tightening, not an expand-only violation).
--
-- ── WHY (ticket: RD-1147) ────────────────────────────────────────
-- RD-1147 moves access_logs (the append-only access audit trail + its
-- tamper-evident hash chain, checkpoints, and anchor) into its own Postgres.
-- In the MAIN database, migration 058 deliberately left the app role with full
-- CRUD on access_logs because the retention prune (90-day TTL + FIFO row cap)
-- runs under the app credential there. In the ISOLATED audit database that
-- concern goes away: prune runs under the SEPARATE admin/owner DSN
-- (AUDIT_ADMIN_DATABASE_URL). So the runtime DSN (AUDIT_DATABASE_URL) can — and
-- MUST — be sealed to append-only, matching every other audit-forever table.
-- The seal means a compromised proxy process (or a leaked runtime credential)
-- can append new access-log rows but CANNOT rewrite or delete history and then
-- recompute the chain forward. Defense in depth, not a silver bullet.
--
-- ── AFFECTED ─────────────────────────────────────────────────────
-- Role: privacy_proxy_app. Table: access_logs (this database only).
-- No data rows are rewritten — this is a grant change, not a data migration.
-- The runtime role KEEPS: SELECT, INSERT on access_logs; SELECT, INSERT, UPDATE
-- on audit_chain_anchor (unchanged from 058 — anchor is read-modify-write and
-- is itself append-only, no DELETE); SELECT, INSERT on audit_chain_checkpoint /
-- audit_chain_reanchor if granted. The runtime role LOSES: UPDATE, DELETE on
-- access_logs.
--
-- Detection query (rows/grants left in a non-sealed state for manual review):
--   SELECT grantee, privilege_type
--   FROM information_schema.role_table_grants
--   WHERE table_name = 'access_logs' AND grantee = 'privacy_proxy_app';
-- After this migration that query must return only SELECT and INSERT. If it
-- still shows UPDATE or DELETE, the runtime DSN is connecting as a role OTHER
-- than privacy_proxy_app (e.g. the DB owner) — the seal will NOT bite; fix the
-- deployment so AUDIT_DATABASE_URL uses the restricted role. (See the deployment
-- note in docs/configuration.)
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- The authoritative, traceable record of this change is this migration file
-- (git) + PR review + tern schema_version (applied-at timestamp). This
-- migration writes NOTHING to any hash-chained audit table (rbac_audit_log,
-- access_logs) — doing so would trip the integrity verifier's tamper alarm.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (privilege-narrowing REVOKE; no DROP of table/column/
-- index/constraint). Role separation: STRENGTHENED — this is the whole point.
-- Runs ONLY against the audit database (embedded in internal/db/migrations_audit,
-- applied by the audit-admin pool). Never runs against the main DATABASE_URL.

-- The grant only exists once migration 058 has created the role. In the audit
-- database the shared FS (which includes 058) runs first, so privacy_proxy_app
-- exists here. Guard defensively anyway so a bare/partial audit DB does not
-- error the migration out.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        -- Seal: remove the ability to rewrite or delete audit history.
        REVOKE UPDATE, DELETE ON access_logs FROM privacy_proxy_app;
        -- Re-assert the append + read grant (idempotent; makes the intended
        -- end-state explicit and independent of 058's exact wording).
        GRANT SELECT, INSERT ON access_logs TO privacy_proxy_app;
        -- The chained INSERT reserves ids via nextval('access_logs_id_seq');
        -- the writer still needs the sequence. (Idempotent re-assert.)
        GRANT USAGE, UPDATE ON SEQUENCE access_logs_id_seq TO privacy_proxy_app;
    END IF;
END$$;

COMMENT ON TABLE access_logs IS
    'Append-only access audit trail (RD-1147). In the separate audit database the runtime role privacy_proxy_app has INSERT+SELECT only; UPDATE/DELETE (retention prune) run under the admin/owner DSN. Tamper-evident hash chain + signed checkpoints anchored here.';
