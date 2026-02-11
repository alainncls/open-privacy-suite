#!/usr/bin/env bash
BACKEND_PORT="${BACKEND_HOST_PORT:-8080}"

echo ""
echo "========================================="
echo "  Services are starting up..."
echo "========================================="
echo "  App:    http://localhost:5173"
echo "  Admin:  http://localhost:5173/admin/dashboard"
echo "  API:    http://localhost:${BACKEND_PORT}"
echo "========================================="
