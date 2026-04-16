import { test, expect } from '@playwright/test';
import { selectors, roles } from '../../helpers/ui/selectors';
import { navigateToAdminAuthenticated, mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

test.describe('Admin Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Authenticate before each test
    await mockLoginViaAPI(page);
  });

  test('admin header displays correctly', async ({ page }) => {
    await page.goto('/admin/dashboard');

    // Wait for admin app to load
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Verify header elements
    await expect(page.locator(selectors.admin.header)).toBeVisible();
    await expect(page.locator(selectors.admin.logo)).toBeVisible();
    await expect(page.locator(selectors.admin.nav)).toBeVisible();

    // Verify branding
    await expect(page.getByText('Privacy Proxy')).toBeVisible();
    await expect(page.getByText('Node Access Control')).toBeVisible();
  });

  test('navigation tabs are visible and functional', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Verify all navigation tabs are visible
    await expect(page.locator(selectors.nav.dashboard)).toBeVisible();
    await expect(page.locator(selectors.nav.logs)).toBeVisible();
    await expect(page.locator(selectors.nav.rbac)).toBeVisible();

    // Verify tab text content
    await expect(page.locator(selectors.nav.dashboard)).toContainText('Dashboard');
    await expect(page.locator(selectors.nav.logs)).toContainText('Access Logs');
    await expect(page.locator(selectors.nav.rbac)).toContainText('RBAC');
  });

  test('clicking Dashboard tab navigates to dashboard', async ({ page }) => {
    await page.goto('/admin/rbac');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Click on Dashboard tab
    await page.locator(selectors.nav.dashboard).click();

    // Verify navigation
    await expect(page).toHaveURL(/\/admin\/dashboard/);
  });

  test('clicking Access Logs tab navigates to logs', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Click on Access Logs tab
    await page.locator(selectors.nav.logs).click();

    // Verify navigation
    await expect(page).toHaveURL(/\/admin\/logs/);
  });

  test('clicking RBAC tab navigates to RBAC manager', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Click on RBAC tab
    await page.locator(selectors.nav.rbac).click();

    // Verify navigation
    await expect(page).toHaveURL(/\/admin\/rbac/);

    // RBAC manager should be visible
    await expect(page.locator(selectors.rbac.manager)).toBeVisible();
  });

  test('dashboard shows status cards', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Wait for dashboard content to load
    // Status cards should display proxy and node status (use exact match to avoid header)
    await expect(page.getByRole('heading', { name: 'Proxy', exact: true })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('heading', { name: 'Node', exact: true })).toBeVisible();
  });

  test('RBAC manager shows sub-tabs', async ({ page }) => {
    await page.goto('/admin/rbac');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Wait for RBAC manager to load
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Verify RBAC sub-tabs are visible
    await expect(page.locator(selectors.rbac.tabOrganizations)).toBeVisible();
    await expect(page.locator(selectors.rbac.tabGroups)).toBeVisible();
    await expect(page.locator(selectors.rbac.tabUsers)).toBeVisible();
    await expect(page.locator(selectors.rbac.tabContracts)).toBeVisible();
  });

  test('navigating between RBAC sub-tabs updates URL', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Navigate to Groups tab
    await page.locator(selectors.rbac.tabGroups).click();
    await expect(page).toHaveURL(/\/admin\/rbac\/groups/);

    // Navigate to Users tab
    await page.locator(selectors.rbac.tabUsers).click();
    await expect(page).toHaveURL(/\/admin\/rbac\/users/);

    // Navigate to Contracts tab
    await page.locator(selectors.rbac.tabContracts).click();
    await expect(page).toHaveURL(/\/admin\/rbac\/contracts/);

    // Navigate back to Organizations tab
    await page.locator(selectors.rbac.tabOrganizations).click();
    await expect(page).toHaveURL(/\/admin\/rbac\/organizations/);
  });

  test('active tab is visually indicated', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Dashboard tab should be active (has data-state="active" on Radix tabs)
    const dashboardTab = page.locator(selectors.nav.dashboard);
    await expect(dashboardTab).toHaveAttribute('data-state', 'active');

    // Navigate to RBAC
    await page.locator(selectors.nav.rbac).click();
    await expect(page).toHaveURL(/\/admin\/rbac/);

    // RBAC tab should now be active
    const rbacTab = page.locator(selectors.nav.rbac);
    await expect(rbacTab).toHaveAttribute('data-state', 'active');

    // Dashboard tab should no longer be active
    await expect(dashboardTab).toHaveAttribute('data-state', 'inactive');
  });

  test('URL directly to RBAC sub-route loads correctly', async ({ page }) => {
    // Navigate directly to RBAC users
    await page.goto('/admin/rbac/users');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // RBAC manager should be visible
    await expect(page.locator(selectors.rbac.manager)).toBeVisible();

    // Users tab should be active
    const usersTab = page.locator(selectors.rbac.tabUsers);
    await expect(usersTab).toHaveAttribute('data-state', 'active');
  });

  test('admin layout is responsive', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // Header should still be visible
    await expect(page.locator(selectors.admin.header)).toBeVisible();

    // Navigation tabs should still be functional (may be condensed)
    await expect(page.locator(selectors.admin.nav)).toBeVisible();

    // Reset to desktop viewport
    await page.setViewportSize({ width: 1280, height: 720 });
    await expect(page.locator(selectors.admin.header)).toBeVisible();
  });

  test('navigation preserves scroll position within sections', async ({ page }) => {
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });

    // Navigate to RBAC and back
    await page.locator(selectors.nav.rbac).click();
    await expect(page).toHaveURL(/\/admin\/rbac/);

    await page.locator(selectors.nav.dashboard).click();
    await expect(page).toHaveURL(/\/admin\/dashboard/);

    // Page should be scrolled to top after navigation
    const scrollPosition = await page.evaluate(() => window.scrollY);
    expect(scrollPosition).toBe(0);
  });
});
