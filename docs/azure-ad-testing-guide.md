# Azure AD / Microsoft Entra ID Setup Guide

## Prerequisites

### 1. Get an Azure AD tenant

Go to https://developer.microsoft.com/en-us/microsoft-365/dev-program — Microsoft gives a free developer tenant with 25 E5 licenses. Alternatively, any personal Microsoft account works if you register the app with "Any org + personal accounts".

### 2. Register an app in Azure Portal

1. Go to https://portal.azure.com → **Microsoft Entra ID** → **App registrations** → **New registration**
2. Name: anything (e.g., "Privacy Proxy Dev")
3. Supported account types: "Single tenant" (your org only) or "Any org + personal" for testing
4. Redirect URI: **Web** → `http://localhost:5173/auth/azure/callback`
5. After creating, note the **Application (client) ID** and **Directory (tenant) ID**
6. Go to **Certificates & secrets** → **New client secret** → copy the value

### 3. Configure environment variables

Add to your `.env`:

```bash
AZURE_AD_CLIENT_ID=<application-client-id>
AZURE_AD_CLIENT_SECRET=<client-secret-value>
AZURE_AD_TENANT_ID=<directory-tenant-id>
ADMIN_API_TOKEN=<any-secret-string-for-admin-api>
```

`ADMIN_API_TOKEN` is needed to bootstrap the tenant allowlist (step 5).

## Setup

### 4. Start the stack

```bash
docker-compose up -d
```

Verify Azure AD is enabled in the backend logs:

```bash
docker-compose logs proxy-backend | grep "Azure AD"
# Should show: Azure AD authentication enabled (tenant: <your-tenant-id>)
```

### 5. Add your tenant to the allowlist (bootstrap)

This is a one-time setup step. The backend maintains an allowlist of Azure AD tenants that are permitted to log in. The `.env` tenant ID configures which Azure AD app handles OAuth — the allowlist controls which tenants can actually authenticate.

Since you can't access the admin UI until you're logged in, use the admin API with `X-Admin-Token`:

```bash
export ADMIN_API_TOKEN=<same-value-as-in-env>

curl -X POST http://localhost:8080/api/v1/admin/azure-tenants \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: ${ADMIN_API_TOKEN}" \
  -d '{
    "tenant_id": "<your-directory-tenant-id>",
    "label": "My Org",
    "auto_provision": true
  }'
```

- `tenant_id` — your Azure AD Directory (tenant) ID (same as `AZURE_AD_TENANT_ID`)
- `auto_provision` — when `true`, users from this tenant are automatically created on first login
- `default_org_id` / `default_group_id` — (optional) auto-place new users into an org/group

After this, you can manage tenants from the admin UI at **RBAC → Azure Tenants**.

## Testing the Flow

### 6. Full login flow

1. Open `http://localhost:5173/login`
2. You should see two tabs: **Privado ID** and **Microsoft**
3. Click the **Microsoft** tab → click **Continue with Microsoft**
4. Sign in with your Microsoft account
5. Microsoft redirects back to `/auth/azure/callback`
6. The callback page exchanges the code for JWT tokens
7. You land on `/link-wallet`

### Verification checklist

| Step | What to check |
|------|--------------|
| Login page | Microsoft tab visible, Privado QR still works |
| Microsoft redirect | URL contains your `client_id`, correct `redirect_uri` |
| Callback | Spinner shows "Completing Microsoft sign-in...", no errors |
| After login | JWT works — user appears in admin UI under Users |
| Admin UI | User shows with `azuread:{oid}` subject |
| Tenant not in allowlist | Remove tenant → login returns 403 |

## Smoke Tests (No Azure Tenant Needed)

You can verify the UI without a real Azure tenant:

1. `GET /api/v1/auth/providers` — returns `["privado"]` when Azure not configured, `["privado", "azuread"]` when it is
2. Login page renders correctly with/without the Microsoft tab
3. Visit `/auth/azure/callback?error=access_denied&error_description=User+cancelled` — error UI shows
4. Visit `/auth/azure/callback` (no params) — shows "Missing code or state" error
5. Visit `/auth/azure/callback?code=fake&state=fake` — shows backend error (invalid state)

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| No Microsoft tab on login page | Env vars not passed to container | Check `AZURE_AD_CLIENT_ID` and `AZURE_AD_CLIENT_SECRET` are in `docker-compose.yml` environment section and `.env` |
| 403 "tenant is not authorized" | Tenant not in allowlist | Add tenant via admin API (step 5) |
| 404 on callback URL | Vite proxy intercepting `/auth/*` | Ensure Vite proxy only matches `/auth/callback`, not `/auth/azure/callback` |
| AADSTS50011 "redirect URI does not match" | Wrong redirect URI in Azure Portal | Set to `http://localhost:5173/auth/azure/callback` |
| "nonce mismatch" | State/session expired | Try again — state tokens have 10-minute TTL |
| "tid claim missing" | Unusual Azure AD configuration | Check the id_token claims in browser devtools |
