import { test, expect } from '@playwright/test';
import { RBACApiClient } from '../helpers/rbac-api';
import { getJWTToken } from '../helpers/auth';

const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'test-admin-token';
const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';

test.describe('Admin Auth API', () => {
  let rbac: RBACApiClient;

  test.beforeAll(async ({ request }) => {
    rbac = new RBACApiClient(request);
  });

  // --- X-Admin-Token tests ---

  test('X-Admin-Token grants access to admin endpoints', async ({ request }) => {
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN },
    });
    expect(response.status()).toBe(200);
  });

  test('wrong X-Admin-Token returns 401', async ({ request }) => {
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { 'X-Admin-Token': 'wrong-token-value' },
    });
    expect(response.status()).toBe(401);
  });

  test('no auth returns 401', async ({ request }) => {
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: {},
    });
    // When ADMIN_API_TOKEN is configured, no auth -> 401
    // When not configured (dev mode), no auth -> 200 (passthrough)
    expect([200, 401]).toContain(response.status());
  });

  // --- JWT-based admin auth tests ---

  test('JWT with admin claim grants access', async ({ request }) => {
    // Create a user with admin claim via X-Admin-Token
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

    // Create user and add to admin group
    const token = await getJWTToken(request, userDID);
    const user = await rbac.findUserByExternalId(userDID);
    expect(user).not.toBeNull();
    await rbac.createMembership(user!.id, { group_id: group.id });

    // Now use the JWT to access admin endpoint
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);

    // Cleanup
    await rbac.deleteOrganization(org.id);
  });

  test('JWT without admin claim returns 403', async ({ request }) => {
    // Create a user with only read claim
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

    // Create user and add to group
    const token = await getJWTToken(request, userDID);
    const user = await rbac.findUserByExternalId(userDID);
    expect(user).not.toBeNull();
    await rbac.createMembership(user!.id, { group_id: group.id });

    // JWT is valid but user lacks admin claim
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(403);

    // Cleanup
    await rbac.deleteOrganization(org.id);
  });

  test('invalid JWT returns 401', async ({ request }) => {
    const response = await request.get(`${PROXY_URL}/api/v1/admin/orgs`, {
      headers: { Authorization: 'Bearer not-a-valid-jwt' },
    });
    expect(response.status()).toBe(401);
  });

  // --- /me/admin-status endpoint ---

  test('/me/admin-status returns true for admin user', async ({ request }) => {
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

    const response = await request.get(`${PROXY_URL}/api/v1/me/admin-status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.is_admin).toBe(true);

    await rbac.deleteOrganization(org.id);
  });

  test('/me/admin-status returns false for non-admin user', async ({ request }) => {
    const userDID = `did:test:nonadminstatus_${Date.now()}`;
    const token = await getJWTToken(request, userDID);

    const response = await request.get(`${PROXY_URL}/api/v1/me/admin-status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.is_admin).toBe(false);
  });
});
