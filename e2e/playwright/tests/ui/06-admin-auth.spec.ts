import { test, expect } from '@playwright/test';
import { RBACApiClient } from '../../helpers/rbac-api';
import {
  mockLoginViaAPI,
  clearAuth,
  getAuthTokens,
} from '../../helpers/ui/auth-helpers';
import { selectors } from '../../helpers/ui/selectors';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';

// Test fixtures created in beforeAll and cleaned up in afterAll.
let adminDID: string;
let nonAdminDID: string;
let orgId: string;

test.describe('Admin Dashboard Auth', () => {
  test.beforeAll(async ({ browser }) => {
    // Use a separate API context with X-Admin-Token for setup.
    const adminToken = process.env.ADMIN_API_TOKEN || 'test-admin-token';
    const context = await browser.newContext({
      baseURL: PROXY_URL,
      extraHTTPHeaders: {
        'Content-Type': 'application/json',
        'X-Admin-Token': adminToken,
      },
    });
    const request = context.request;
    const rbac = new RBACApiClient(request);

    // Create org + group with admin claim
    const suffix = Date.now();
    adminDID = `did:test:ui_admin_${suffix}`;
    nonAdminDID = `did:test:ui_nonadmin_${suffix}`;

    const org = await rbac.createOrganization({
      slug: `ui-admin-org-${suffix}`,
      name: 'UI Admin Test Org',
    });
    orgId = org.id;

    const group = await rbac.createGroup(org.id, {
      slug: `ui-admin-group-${suffix}`,
      name: 'UI Admin Group',
    });
    await rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['admin'],
    });

    // Authenticate both users (creates them in DB via auto-provision)
    await getAuthTokens(adminDID);
    await getAuthTokens(nonAdminDID);

    // Add only the admin user to the admin group
    const adminUser = await rbac.findUserByExternalId(adminDID);
    expect(adminUser).not.toBeNull();
    await rbac.createMembership(adminUser!.id, { group_id: group.id });

    await context.close();
  });

  test.afterAll(async ({ browser }) => {
    const adminToken = process.env.ADMIN_API_TOKEN || 'test-admin-token';
    const context = await browser.newContext({
      baseURL: PROXY_URL,
      extraHTTPHeaders: {
        'Content-Type': 'application/json',
        'X-Admin-Token': adminToken,
      },
    });
    const rbac = new RBACApiClient(context.request);

    try {
      await rbac.deleteOrganization(orgId);
    } catch {
      // Best-effort cleanup
    }

    await context.close();
  });

  test('admin user can access admin dashboard', async ({ page }) => {
    await mockLoginViaAPI(page, adminDID);
    await page.goto('/admin/dashboard');

    // Should see the admin app (not access denied)
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 15000 });
  });

  test('non-admin user sees access denied', async ({ page }) => {
    await mockLoginViaAPI(page, nonAdminDID);
    await page.goto('/admin/dashboard');

    // Should see the "Access Denied" message
    await expect(page.getByText('Access Denied')).toBeVisible({ timeout: 15000 });
    await expect(
      page.getByText("You don't have admin privileges")
    ).toBeVisible();

    // Should NOT see the admin app
    await expect(page.locator(selectors.admin.app)).not.toBeVisible();
  });

  test('unauthenticated user is redirected to login', async ({ page }) => {
    await page.goto('/login');
    await clearAuth(page);

    await page.goto('/admin/dashboard');

    // RequireAuth should redirect to /login
    await expect(page).toHaveURL(/\/login/, { timeout: 15000 });
  });

  test('clearing auth and reloading redirects to login', async ({ page }) => {
    // First, log in as admin and verify dashboard loads
    await mockLoginViaAPI(page, adminDID);
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 15000 });

    // Clear auth and reload
    await clearAuth(page);
    await page.reload();

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/, { timeout: 15000 });
  });
});
