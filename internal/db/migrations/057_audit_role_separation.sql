-- 057_audit_role_separation.sql
-- RD-858: split Postgres roles so the application identity cannot
-- silently rewrite the audit chain. Pre-fix, a single role had full
-- read/write/delete on every table — an attacker who compromised the
-- proxy host could rewrite rbac_audit_log entries and recompute the
-- chain forward in seconds. Role separation raises that bar to "the
-- attacker must also pop the dedicated admin credential" — defense in
-- depth, not a silver bullet, but the cheapest meaningful step that
-- doesn't require leaving Postgres trust boundaries.
--
-- Roles defined:
--   * privacy_proxy_app   — the runtime identity used by the proxy
--                           process. INSERT-only on append-forever
--                           audit tables (rbac_audit_log,
--                           compliance_logs); INSERT/UPDATE/DELETE on
--                           access_logs (retention prune is intentional
--                           policy on that table); SELECT on all
--                           tables; full CRUD on the rest of the
--                           schema needed for normal operation.
--   * privacy_proxy_admin — operator identity for migrations, ad-hoc
--                           queries, incident response. Full DDL/DML
--                           on the entire schema. Used **rarely**, by
--                           a human via a credential that lives
--                           outside the app's secret store.
--
-- Credential lifecycle is intentionally NOT set by this migration:
--   - No passwords are assigned (NOLOGIN is the default).
--   - The infra team picks the lifecycle (AWS Secrets Manager via
--     IRSA, RDS IAM authentication, HashiCorp Vault dynamic secrets,
--     plain `ALTER ROLE ... PASSWORD ...`, etc.) and applies it via
--     their preferred mechanism after this migration runs.
--   - The operator MUST flip the roles to LOGIN before they can be
--     used: `ALTER ROLE privacy_proxy_app LOGIN PASSWORD '...';`
--     (or equivalent for IAM auth).
--   - See docs/security/db-role-separation.md for the recommended
--     setup (AWS Secrets Manager pattern for canonical deployments).
--
-- IF the operator has NOT separated credentials yet, the migration is
-- still safe — the existing connection role (whatever credential was
-- in DATABASE_URL when migrations ran) remains untouched, with all
-- its current permissions. The new roles sit dormant until the
-- operator chooses to enable them. This means the migration is
-- non-breaking even when role separation is deferred.
--
-- The compliance value (the audit trail of admin actions is harder to
-- tamper with) is only realised when the operator actually changes
-- the app's DATABASE_URL to use privacy_proxy_app instead of a
-- superuser. Until then this is "infrastructure ready, policy not
-- enforced" — flagged in docs.

-- ---------------------------------------------------------------------------
-- Idempotent role creation — DO blocks because CREATE ROLE doesn't
-- support IF NOT EXISTS as a keyword.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        CREATE ROLE privacy_proxy_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_admin') THEN
        CREATE ROLE privacy_proxy_admin NOLOGIN;
    END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Admin role: full access. The "carve-out" path for emergency surgery.
-- Granted at schema level so future tables / sequences inherit the
-- permission automatically (alongside the explicit defaults below).
-- ---------------------------------------------------------------------------

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO privacy_proxy_admin;
GRANT USAGE ON SCHEMA public TO privacy_proxy_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES TO privacy_proxy_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO privacy_proxy_admin;

-- ---------------------------------------------------------------------------
-- App role: full CRUD on the operational schema, EXCEPT the
-- append-forever audit tables (rbac_audit_log, compliance_logs).
--
-- Strategy: GRANT ALL by default, then REVOKE UPDATE/DELETE on the
-- two protected tables. Easier to keep correct than enumerating every
-- operational table individually as the schema grows.
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO privacy_proxy_app;
GRANT USAGE, UPDATE ON ALL SEQUENCES IN SCHEMA public TO privacy_proxy_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO privacy_proxy_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, UPDATE ON SEQUENCES TO privacy_proxy_app;

-- rbac_audit_log: INSERT and SELECT only. No UPDATE / DELETE — an
-- attacker holding the app role cannot rewrite admin-action history.
-- The retention worker is moved to the admin role (see
-- internal/audit/retention.go); operators who run retention against
-- this table must supply admin creds.
REVOKE UPDATE, DELETE, TRUNCATE ON rbac_audit_log FROM privacy_proxy_app;

-- compliance_logs: same shape. Travel-rule decisions and sanction-hit
-- records are forever-append for regulatory reasons.
REVOKE UPDATE, DELETE, TRUNCATE ON compliance_logs FROM privacy_proxy_app;

-- access_logs: pruning is intentional policy (90-day retention by
-- default, plus the FIFO row-cap sweep). The app role KEEPS
-- UPDATE/DELETE/TRUNCATE so the retention worker continues to run
-- under the app role — different trust assumption from the two
-- append-forever tables above.

COMMENT ON ROLE privacy_proxy_app IS
    'Runtime app role (RD-858). INSERT-only on rbac_audit_log + compliance_logs; full CRUD elsewhere. No password set by migration — infra team configures credential lifecycle.';

COMMENT ON ROLE privacy_proxy_admin IS
    'Admin / operator role (RD-858). Full DDL+DML. Used rarely, via credentials that live outside the app secret store. No password set by migration.';
