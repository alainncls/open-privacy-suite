## Travel Rule Enforcement via Blockchain Proxy (Off-Chain DATA Analysis)

### Concept

A **proxy node/gateway** sits between the VASP (or wallet) and the EVM RPC endpoint. It intercepts `eth_sendRawTransaction` calls, decodes the transaction's `data` field, applies travel rule logic, and either **relays or rejects** the transaction — all before it hits the mempool.

### Architecture

```
Wallet/VASP → [RPC Proxy] → EVM Node
                  │
                  ├─ Decode raw tx
                  ├─ Parse DATA field
                  ├─ Apply travel rule policy
                  ├─ ✅ Forward  or  ❌ Reject
                  │
                  └─ Travel Rule DB (IVMS101 records)

```

### What the Proxy Does

**1. Intercept** — Catches all `eth_sendRawTransaction` and `eth_sendTransaction` JSON-RPC calls.

**2. Decode** — RLP-decodes the signed transaction to extract `to`, `value`, `data`, `from` (recovered from signature).

**3. Analyze the DATA field:**

- **Empty data + value > 0** → native ETH transfer. Check amount against threshold.
- **Selector `0xa9059cbb`** → ERC-20 `transfer(address,uint256)`. Decode recipient and amount, price the token, check threshold.
- **Selector `0x23b872dd`** → ERC-20 `transferFrom`. Same logic.
- **Known DEX/bridge selectors** → Decode swap paths, destination chains, recipients. Flag if obfuscating beneficiary.
- **Unknown selector** → Lookup against ABI registry or 4byte.directory, attempt decode, apply conservative policy.

**4. Enforce** — Based on decoded intent:

| Condition | Action |
|---|---|
| Transfer < threshold | Pass through |
| Transfer ≥ threshold + valid travel rule record exists in DB | Pass through |
| Transfer ≥ threshold + no travel rule record | **Reject with error** |
| Interaction with sanctioned address | **Reject** |
| Undecodable DATA to unknown contract | Policy-dependent (reject / flag / allow) |

**5. Log** — Record decision, decoded parameters, and compliance metadata for audit.

### Key Design Points

- **No on-chain changes** — purely infrastructure-level enforcement.
- **Token pricing** — proxy needs a price oracle (API-based) to convert token amounts to fiat for threshold checks.
- **ABI registry** — maintain a mapping of known selectors → decode logic. Cover ERC-20, ERC-721, major DEX routers, bridges.
- **Travel rule record DB** — VASPs submit IVMS101 payloads (originator/beneficiary PII) via a separate API *before* sending the transaction. The proxy checks this DB at relay time.
- **Bypass risk** — users can submit directly to another node. This only works when the proxy is the **mandatory gateway** (e.g., regulated VASP infra, or a compliant RPC provider like Infura/Alchemy adding this layer).



