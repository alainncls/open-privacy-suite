-- Add contract function selectors for fine-grained access control
-- Allows restricting which contract functions a group can call

-- Add contract_functions column to group_permissions
-- JSON structure: {"0xcontract_address": ["0xselector1", "0xselector2"], ...}
-- If empty or null, all functions are allowed on allowed contracts
-- If contract is specified, only listed selectors are allowed
ALTER TABLE group_permissions
ADD COLUMN IF NOT EXISTS contract_functions JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Add same column to effective_permissions_cache
ALTER TABLE effective_permissions_cache
ADD COLUMN IF NOT EXISTS contract_functions JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Add index for contract_functions lookups
CREATE INDEX IF NOT EXISTS idx_group_permissions_contract_functions
ON group_permissions USING GIN (contract_functions);

---- create above / drop below ----

-- Remove indexes
DROP INDEX IF EXISTS idx_group_permissions_contract_functions;

-- Remove columns
ALTER TABLE effective_permissions_cache DROP COLUMN IF EXISTS contract_functions;
ALTER TABLE group_permissions DROP COLUMN IF EXISTS contract_functions;
