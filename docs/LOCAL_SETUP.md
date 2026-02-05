# Privacy Proxy - Local Setup

Quick guide to run privacy-proxy locally for development and testing.

## Step 1: Get Your LAN IP (for network access)

If you want to access from other devices on your network:

```bash
# macOS
ipconfig getifaddr en0

# Linux
hostname -I | awk '{print $1}'
```

## Step 2: Start Services

```bash
# Local only (localhost access)
make run

# OR for LAN access (replace with your IP)
BASE_URL="http://192.168.1.100:8080" make run
```

## Step 3: Useful Commands

| Command | Description |
|---------|-------------|
| `make run` | Start all services (postgres, anvil, backend, frontend) |
| `make stop` | Stop all services |
| `make restart` | Restart all services |
| `make logs` | View live logs |
| `make status` | Show service status |
| `make clean` | Stop and remove volumes |

## Step 4: URLs

| Console | URL |
|---------|-----|
| **User Login** | http://localhost:5173 |
| **Admin Console** | http://localhost:5173/admin |
| **API** | http://localhost:8080 |

For LAN access, replace `localhost` with your IP.

## Step 5: Dev Mode Authentication

1. Open http://localhost:5173
2. Click the **flask icon** below the QR code for instant mock login
3. You'll be logged in with a test DID - no real wallet needed

## Quick Test

```bash
# Check everything is running
make status

# Watch logs
make logs
```

## Troubleshooting

**Port already in use?**
```bash
BACKEND_HOST_PORT=8081 POSTGRES_HOST_PORT=5433 BASE_URL="http://YOUR_IP:8081" make run
```

**Services not starting?**
```bash
make clean
make run
```

**Need to rebuild containers?**
```bash
make restart
```
