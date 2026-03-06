# Privacy Proxy

A privacy-preserving JSON-RPC proxy for Ethereum nodes with ZK-proof authentication and hierarchical RBAC.

## Quick Start

```bash
# Start the stack
make run

# Open admin UI
open http://localhost:5173
```

In development mode, click the flask icon on the login page for instant mock authentication.

## Architecture

```
┌─────────────┐     ┌───────────────────────────────────────┐     ┌──────────────┐
│   Client    │────>│            Privacy Proxy              │────>│  Ethereum    │
│  (Wallet)   │     │                                       │     │    Node      │
└─────────────┘     │  ┌─────────┐  ┌──────┐  ┌─────────┐  │     └──────────────┘
                    │  │  Auth   │  │ RBAC │  │  Proxy  │  │
                    │  │ (ZK/JWT)│  │      │  │         │  │
                    │  └─────────┘  └──────┘  └─────────┘  │
                    │                  │                    │
                    │           ┌──────▼──────┐            │
                    │           │  PostgreSQL │            │
                    │           └─────────────┘            │
                    └───────────────────────────────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| proxy-backend | 8080 | API server |
| proxy-frontend | 5173 | Admin UI |
| postgres | 5432 | Database |
| anvil | 8545 | Local Ethereum node |

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](site/src/app/docs/getting-started/page.mdx) | Installation, setup, first run |
| [Architecture](site/src/app/docs/architecture/page.mdx) | System overview, request flow, components |
| [Authentication](site/src/app/docs/authentication/page.mdx) | ZK-proof auth, ETH address linking |
| [Azure AD / SSO](site/src/app/docs/azure-ad/page.mdx) | Microsoft Entra ID integration |
| [RBAC](site/src/app/docs/rbac/page.mdx) | Role-based access control system |
| [API Reference](site/src/app/docs/api/page.mdx) | Complete HTTP endpoint documentation |
| [Security](site/src/app/docs/security/page.mdx) | Request filtering, cross-org isolation |
| [Compliance](site/src/app/docs/compliance/page.mdx) | Travel rule enforcement |
| [Selective Disclosure](site/src/app/docs/disclosure/page.mdx) | Privacy-aware data sharing |
| [Contract Deployment](site/src/app/docs/deployment/page.mdx) | Deploying contracts through the proxy |
| [Configuration](site/src/app/docs/configuration/page.mdx) | Environment variables reference |
| [Testing](site/src/app/docs/testing/page.mdx) | Unit, E2E, and Playwright tests |
| [Troubleshooting](site/src/app/docs/troubleshooting/page.mdx) | Common issues and fixes |

To run the docs site locally:

```bash
make site-dev
# Open http://localhost:3000
```

## Testing

```bash
make test-unit   # Go unit tests
make e2e         # Playwright E2E tests (131+ tests)
```

## License

MIT
