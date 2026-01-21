# Privacy Proxy Documentation

A privacy-preserving JSON-RPC proxy for Ethereum nodes with ZK-proof authentication and hierarchical RBAC.

## Architecture

```
┌─────────────┐     ┌───────────────────────────────────────┐     ┌──────────────┐
│   Client    │────▶│            Privacy Proxy              │────▶│  Ethereum    │
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

## Core Components

| Component | Description |
|-----------|-------------|
| **Authentication** | Privado ID ZK proofs with optional ProofOfHumanity |
| **Authorization** | Hierarchical RBAC with method/contract whitelisting |
| **Proxy** | JSON-RPC forwarding with security filtering |
| **Rate Limiting** | Per-user RPS and daily request limits |

## Documentation Index

| Document | Description |
|----------|-------------|
| [API Reference](API.md) | Complete HTTP endpoint documentation |
| [Authentication](AUTHENTICATION.md) | ZK-proof auth flow and ETH address linking |
| [RBAC](RBAC.md) | Role-based access control system |
| [Configuration](CONFIGURATION.md) | Environment variables and settings |
| [Testing](TESTING.md) | Test infrastructure and running tests |
| [Security](SECURITY.md) | Security features and considerations |

## Quick Start

```bash
# Start with Docker
docker-compose up -d

# Or run locally
make db-migrate
go run ./cmd/server
```

**Endpoints:**
- API: http://localhost:8080
- Frontend: http://localhost:5173
- Admin API: http://localhost:8080/api (localhost only)

## Request Flow

1. **Authenticate**: `POST /auth/request` → receive auth challenge
2. **Prove**: Wallet generates ZK proof → `POST /auth/callback`
3. **Receive JWT**: Server issues access + refresh tokens
4. **Call RPC**: `POST /` with `Authorization: Bearer <token>`
5. **Refresh**: `POST /refresh` when access token expires
