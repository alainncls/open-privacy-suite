import { test, expect } from '@playwright/test';
import { RBACApiClient } from '../helpers/rbac-api';
import { getJWTToken } from '../helpers/auth';

const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token';
const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';

test.describe('Admin Auth API', () => {
  // rbac client uses the default request context which has X-Admin-Token
  let rbac: RBACApiClient;

  test.beforeAll(async ({ request }) => {
    rbac = new RBACApiClient(request);
  });

  // --- X-Admin-Token tests ---

  test('X-Admin-Token grants access to admin endpoints', async ({ request }) => {
    // Default request context already has X-Admin-Token via extraHTTPHeaders
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`);
    expect(response.status()).toBe(200);
  });

  test('wrong X-Admin-Token returns 401', async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { 'X-Admin-Token': 'wrong-token-value' },
    });
    expect(response.status()).toBe(401);
    await ctx.dispose();
  });

  test('no auth returns 401', async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/admin/orgs`);
    expect(response.status()).toBe(401);
    await ctx.dispose();
  });

  // --- JWT-based admin auth tests ---

  test('JWT with admin claim grants access', async ({ request, playwright }) => {
    const userDID = `did:test:admin_e2e_${Date.now()}`;
    const org = await rbac.createOrganization({
      slug: `admin-test-org-${Date.now()}`,
      name: 'Admin Test Org',
    });
    const group = await rbac.createGroup(org.id, {
      slug: `admin-test-group-${Date.now()}`,
      name: 'Admin Test Group',
    });
    await rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['admin'],
    });

    // Create user (getJWTToken auto-provisions via mock login)
    const token = await getJWTToken(request, userDID);
    const user = await rbac.findUserByExternalId(userDID);
    expect(user).not.toBeNull();
    await rbac.createMembership(user!.id, { group_id: group.id });

    // Use fresh context with only JWT (no X-Admin-Token)
    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);
    await ctx.dispose();

    await rbac.deleteOrganization(org.id);
  });

  test('JWT without admin claim returns 403', async ({ request, playwright }) => {
    const userDID = `did:test:nonadmin_e2e_${Date.now()}`;
    const org = await rbac.createOrganization({
      slug: `nonadmin-test-org-${Date.now()}`,
      name: 'Non-Admin Test Org',
    });
    const group = await rbac.createGroup(org.id, {
      slug: `nonadmin-test-group-${Date.now()}`,
      name: 'Non-Admin Test Group',
    });
    await rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'],
    });

    const token = await getJWTToken(request, userDID);
    const user = await rbac.findUserByExternalId(userDID);
    expect(user).not.toBeNull();
    await rbac.createMembership(user!.id, { group_id: group.id });

    // Use fresh context with only JWT (no X-Admin-Token)
    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(403);
    await ctx.dispose();

    await rbac.deleteOrganization(org.id);
  });

  test('invalid JWT returns 401', async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { Authorization: 'Bearer not-a-valid-jwt' },
    });
    expect(response.status()).toBe(401);
    await ctx.dispose();
  });

  // --- /me/admin-status endpoint ---

  test('/me/admin-status returns true for admin user', async ({ request, playwright }) => {
    const userDID = `did:test:adminstatus_${Date.now()}`;
    const org = await rbac.createOrganization({
      slug: `status-org-${Date.now()}`,
      name: 'Status Test Org',
    });
    const group = await rbac.createGroup(org.id, {
      slug: `status-group-${Date.now()}`,
      name: 'Status Test Group',
    });
    await rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['admin'],
    });

    const token = await getJWTToken(request, userDID);
    const user = await rbac.findUserByExternalId(userDID);
    expect(user).not.toBeNull();
    await rbac.createMembership(user!.id, { group_id: group.id });

    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/me/admin-status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.is_admin).toBe(true);
    await ctx.dispose();

    await rbac.deleteOrganization(org.id);
  });

  test('/me/admin-status returns false for non-admin user', async ({ request, playwright }) => {
    const userDID = `did:test:nonadminstatus_${Date.now()}`;
    const token = await getJWTToken(request, userDID);

    const ctx = await playwright.request.newContext();
    const response = await ctx.get(`${PROXY_URL}/api/v1/me/admin-status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.is_admin).toBe(false);
    await ctx.dispose();
  });
});
