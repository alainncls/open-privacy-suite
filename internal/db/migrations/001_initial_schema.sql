-- Initial schema for privacy-proxy
-- Consolidated schema including all RBAC tables

-- =============================================================================
-- Legacy tables (for backward compatibility)
-- =============================================================================

CREATE TABLE IF NOT EXISTS access_policies (
    external_id VARCHAR(255) PRIMARY KEY,
    kyc BOOLEAN NOT NULL DEFAULT false,
    allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    banned BOOLEAN NOT NULL DEFAULT false,
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_logs (
    id SERIAL PRIMARY KEY,
    external_id VARCHAR(255) NOT NULL,
    method VARCHAR(100) NOT NULL,
    status_code INTEGER NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash VARCHAR(255) PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- =============================================================================
-- ETH Address Linking
-- =============================================================================

CREATE TABLE IF NOT EXISTS eth_address_links (
    id SERIAL PRIMARY KEY,
    did VARCHAR(255) NOT NULL,
    eth_address VARCHAR(42) NOT NULL,  -- Ethereum address with 0x prefix (lowercase)
    signature VARCHAR(512) NOT NULL,    -- EIP-191 personal_sign signature
    message_hash VARCHAR(66) NOT NULL,  -- Keccak256 hash of the signed message
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP,
    UNIQUE(eth_address)  -- Each ETH address can only be linked to one DID
);

-- =============================================================================
-- RBAC tables
-- =============================================================================

-- Organizations: Top-level tenants
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles: Named permission sets with claims
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    claims JSONB NOT NULL DEFAULT '[]'::jsonb, -- Array of claims: deployer, reader, writer, admin, upgrade
    allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb, -- Allowed JSON-RPC methods
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- Groups: Hierarchical permission containers within organizations
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    slug VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    depth INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL, -- Materialized path for efficient queries (e.g., "root.engineering.devops")
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, slug)
);

-- Group permissions: Per-group method/address allowlists and rate limits
CREATE TABLE IF NOT EXISTS group_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb, -- Allowed JSON-RPC methods
    allow_addresses JSONB NOT NULL DEFAULT '[]'::jsonb, -- Allowed addresses (contracts or EOAs, lowercase)
    owned_addresses JSONB NOT NULL DEFAULT '[]'::jsonb, -- Addresses owned by this group
    address_functions JSONB NOT NULL DEFAULT '{}'::jsonb, -- {"0xaddress": ["0xselector1", ...]} function selectors
    rate_limit_rps INTEGER, -- Requests per second limit (NULL = unlimited)
    rate_limit_daily INTEGER, -- Daily request limit (NULL = unlimited)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id)
);

-- Users: Extended user model for RBAC
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255) UNIQUE NOT NULL, -- User's DID
    kyc BOOLEAN NOT NULL DEFAULT false,
    banned BOOLEAN NOT NULL DEFAULT false,
    note TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User memberships: Links users to groups with roles
CREATE TABLE IF NOT EXISTS user_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'admin', -- 'admin' or 'zk_attested'
    zk_credential_ref TEXT, -- Reference to ZK credential if source is zk_attested
    expires_at TIMESTAMP, -- Optional membership expiration
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, group_id)
);

-- Contract ownership: Tracks deployed contracts and their owner groups
CREATE TABLE IF NOT EXISTS contract_ownership (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_address VARCHAR(42) NOT NULL, -- Ethereum address (lowercase, with 0x prefix)
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    deployed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    deployed_at TIMESTAMP,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(contract_address, org_id)
);

-- Effective permissions cache: Materialized permissions for performance
CREATE TABLE IF NOT EXISTS effective_permissions_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    allow_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    owned_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    address_functions JSONB NOT NULL DEFAULT '{}'::jsonb,
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

-- =============================================================================
-- Indexes
-- =============================================================================

-- Legacy table indexes
CREATE INDEX IF NOT EXISTS idx_logs_external_id ON access_logs(external_id);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON access_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_subject ON refresh_tokens(subject);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_subject ON revoked_tokens(subject);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- ETH address linking indexes
CREATE INDEX IF NOT EXISTS idx_eth_address_links_did ON eth_address_links(did);
CREATE INDEX IF NOT EXISTS idx_eth_address_links_eth_address ON eth_address_links(eth_address);
CREATE INDEX IF NOT EXISTS idx_eth_address_links_active ON eth_address_links(did) WHERE revoked = false;

-- RBAC indexes
CREATE INDEX IF NOT EXISTS idx_groups_org_id ON groups(org_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent_id ON groups(parent_id);
CREATE INDEX IF NOT EXISTS idx_groups_path ON groups(path);
CREATE INDEX IF NOT EXISTS idx_groups_role_id ON groups(role_id);
CREATE INDEX IF NOT EXISTS idx_roles_org_id ON roles(org_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_group_id ON group_permissions(group_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_address_functions ON group_permissions USING GIN (address_functions);
CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id);
CREATE INDEX IF NOT EXISTS idx_user_memberships_user_id ON user_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_user_memberships_group_id ON user_memberships(group_id);
CREATE INDEX IF NOT EXISTS idx_contract_ownership_org_id ON contract_ownership(org_id);
CREATE INDEX IF NOT EXISTS idx_contract_ownership_owner_group_id ON contract_ownership(owner_group_id);
CREATE INDEX IF NOT EXISTS idx_contract_ownership_address ON contract_ownership(contract_address);
CREATE INDEX IF NOT EXISTS idx_effective_permissions_user_org ON effective_permissions_cache(user_id, org_id);
CREATE INDEX IF NOT EXISTS idx_effective_permissions_expires ON effective_permissions_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_actor ON rbac_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_resource ON rbac_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_created ON rbac_audit_log(created_at);

-- =============================================================================
-- Default data
-- =============================================================================

-- Create default organization
INSERT INTO organizations (id, slug, name, settings)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default Organization',
    '{}'::jsonb
)
ON CONFLICT (slug) DO NOTHING;

-- Create default roles
INSERT INTO roles (id, org_id, name, description, claims, allow_methods)
VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'admin', 'Full administrative access', '["admin", "deployer", "writer", "reader"]'::jsonb, '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_call", "eth_estimateGas", "eth_sendRawTransaction", "eth_sendTransaction", "eth_getLogs", "eth_getBlockTransactionCountByHash", "eth_getBlockTransactionCountByNumber", "eth_getUncleCountByBlockHash", "eth_getUncleCountByBlockNumber", "eth_protocolVersion", "eth_syncing", "net_version", "net_listening", "net_peerCount", "web3_clientVersion", "web3_sha3"]'::jsonb),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'deployer', 'Can deploy contracts', '["deployer", "writer", "reader"]'::jsonb, '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_call", "eth_estimateGas", "eth_sendRawTransaction", "eth_sendTransaction", "eth_getLogs", "net_version", "web3_clientVersion"]'::jsonb),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', 'user', 'Standard user access', '["writer", "reader"]'::jsonb, '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_call", "eth_estimateGas", "eth_sendRawTransaction", "eth_sendTransaction", "eth_getLogs", "net_version"]'::jsonb),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000001', 'reader', 'Read-only access', '["reader"]'::jsonb, '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_call", "eth_getLogs", "net_version"]'::jsonb)
ON CONFLICT (org_id, name) DO NOTHING;

-- Create default root group (with admin role)
INSERT INTO groups (id, org_id, parent_id, role_id, slug, name, description, depth, path)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    NULL,
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default Group',
    'Default group for all users',
    0,
    'default'
)
ON CONFLICT (org_id, slug) DO NOTHING;

-- Create default group permissions (allow common JSON-RPC methods)
INSERT INTO group_permissions (id, group_id, allow_methods, allow_addresses, owned_addresses, address_functions)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_call", "eth_estimateGas", "eth_sendRawTransaction", "eth_sendTransaction", "eth_getLogs", "eth_getBlockTransactionCountByHash", "eth_getBlockTransactionCountByNumber", "eth_getUncleCountByBlockHash", "eth_getUncleCountByBlockNumber", "eth_protocolVersion", "eth_syncing", "net_version", "net_listening", "net_peerCount", "web3_clientVersion", "web3_sha3"]'::jsonb,
    '[]'::jsonb,
    '[]'::jsonb,
    '{}'::jsonb
)
ON CONFLICT (group_id) DO NOTHING;

---- create above / drop below ----

-- Drop all indexes
DROP INDEX IF EXISTS idx_rbac_audit_log_created;
DROP INDEX IF EXISTS idx_rbac_audit_log_resource;
DROP INDEX IF EXISTS idx_rbac_audit_log_actor;
DROP INDEX IF EXISTS idx_effective_permissions_expires;
DROP INDEX IF EXISTS idx_effective_permissions_user_org;
DROP INDEX IF EXISTS idx_contract_ownership_address;
DROP INDEX IF EXISTS idx_contract_ownership_owner_group_id;
DROP INDEX IF EXISTS idx_contract_ownership_org_id;
DROP INDEX IF EXISTS idx_user_memberships_group_id;
DROP INDEX IF EXISTS idx_user_memberships_user_id;
DROP INDEX IF EXISTS idx_users_external_id;
DROP INDEX IF EXISTS idx_group_permissions_address_functions;
DROP INDEX IF EXISTS idx_group_permissions_group_id;
DROP INDEX IF EXISTS idx_roles_org_id;
DROP INDEX IF EXISTS idx_groups_role_id;
DROP INDEX IF EXISTS idx_groups_path;
DROP INDEX IF EXISTS idx_groups_parent_id;
DROP INDEX IF EXISTS idx_groups_org_id;
DROP INDEX IF EXISTS idx_eth_address_links_active;
DROP INDEX IF EXISTS idx_eth_address_links_eth_address;
DROP INDEX IF EXISTS idx_eth_address_links_did;
DROP INDEX IF EXISTS idx_revoked_tokens_expires;
DROP INDEX IF EXISTS idx_revoked_tokens_subject;
DROP INDEX IF EXISTS idx_refresh_tokens_expires;
DROP INDEX IF EXISTS idx_refresh_tokens_subject;
DROP INDEX IF EXISTS idx_logs_created_at;
DROP INDEX IF EXISTS idx_logs_external_id;

-- Drop all tables (in reverse dependency order)
DROP TABLE IF EXISTS rbac_audit_log;
DROP TABLE IF EXISTS effective_permissions_cache;
DROP TABLE IF EXISTS contract_ownership;
DROP TABLE IF EXISTS user_memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS group_permissions;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS eth_address_links;
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS access_logs;
DROP TABLE IF EXISTS access_policies;
