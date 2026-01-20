-- ETH address linking schema
-- Links Ethereum addresses to DIDs with signature verification

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

-- Index for looking up addresses by DID
CREATE INDEX IF NOT EXISTS idx_eth_address_links_did ON eth_address_links(did);

-- Index for looking up DID by ETH address
CREATE INDEX IF NOT EXISTS idx_eth_address_links_eth_address ON eth_address_links(eth_address);

-- Index for non-revoked links
CREATE INDEX IF NOT EXISTS idx_eth_address_links_active ON eth_address_links(did) WHERE revoked = false;

---- create above / drop below ----

DROP INDEX IF EXISTS idx_eth_address_links_active;
DROP INDEX IF EXISTS idx_eth_address_links_eth_address;
DROP INDEX IF EXISTS idx_eth_address_links_did;
DROP TABLE IF EXISTS eth_address_links;
