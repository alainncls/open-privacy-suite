-- Add missing RBAC cache and audit tables
-- These were added to 001_initial_schema.sql after it was already applied to some environments

-- Effective permissions cache: Materialized permissions for performance
CREATE TABLE IF NOT EXISTS effective_permissions_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    allow_contracts JSONB NOT NULL DEFAULT '[]'::jsonb,
    owned_contracts JSONB NOT NULL DEFAULT '[]'::jsonb,
    claims JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_limit_rps INTEGER,
    rate_limit_daily INTEGER,
    computed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    UNIQUE(user_id, org_id)
);

-- RBAC audit log: Audit trail for all RBAC changes
CREATE TABLE IF NOT EXISTS rbac_audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID, -- User who performed the action (NULL for system actions)
    actor_external_id VARCHAR(255), -- External ID of actor for reference
    action VARCHAR(50) NOT NULL, -- create, update, delete, assign, revoke
    resource_type VARCHAR(50) NOT NULL, -- organization, group, role, user, membership, etc.
    resource_id UUID, -- ID of the affected resource
    resource_name VARCHAR(255), -- Human-readable name for reference
    old_value JSONB, -- Previous value (for updates)
    new_value JSONB, -- New value
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for effective_permissions_cache
CREATE INDEX IF NOT EXISTS idx_effective_permissions_user_org ON effective_permissions_cache(user_id, org_id);
CREATE INDEX IF NOT EXISTS idx_effective_permissions_expires ON effective_permissions_cache(expires_at);

-- Indexes for rbac_audit_log
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_actor ON rbac_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_resource ON rbac_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_created ON rbac_audit_log(created_at);

---- create above / drop below ----

-- Drop indexes
DROP INDEX IF EXISTS idx_rbac_audit_log_created;
DROP INDEX IF EXISTS idx_rbac_audit_log_resource;
DROP INDEX IF EXISTS idx_rbac_audit_log_actor;
DROP INDEX IF EXISTS idx_effective_permissions_expires;
DROP INDEX IF EXISTS idx_effective_permissions_user_org;

-- Drop tables
DROP TABLE IF EXISTS rbac_audit_log;
DROP TABLE IF EXISTS effective_permissions_cache;
