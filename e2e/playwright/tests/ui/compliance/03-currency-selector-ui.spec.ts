import { test, expect } from '@playwright/test';
import { mockLoginViaAPI } from '../../../helpers/ui/auth-helpers';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token';

test.describe('Currency Selector UI', () => {
  test.beforeEach(async ({ page, request }) => {
    // Ensure currency is reset to USD before each test. The endpoint is
    // gated by requireSuperAdmin so we must send X-Admin-Token (a JWT admin
    // is rejected by design — see admin_compliance.go:setBaseCurrency).
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/currency`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN },
      data: { currency: 'usd' },
    });
    await mockLoginViaAPI(page);

    // Inject the admin token into the page's localStorage so the adminClient
    // sends X-Admin-Token (super-admin) when the UI calls the currency
    // endpoint — without this, the JWT path is used and the backend returns
    // 403 from requireSuperAdmin, silently reverting the in-flight switch.
    await page.addInitScript((token) => {
      window.localStorage.setItem('privacy_proxy_admin_api_token', token);
    }, ADMIN_TOKEN);
  });

  test('displays default USD currency in the selector', async ({ page }) => {
    await page.goto('/admin/compliance/config');

    // Wait for the compliance page to load
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    // Currency selector should show USD
    const selector = page.getByTestId('currency-selector');
    await expect(selector).toBeVisible({ timeout: 5000 });
    await expect(selector).toContainText('$ USD');
  });

  // The currency switch can pop a "Currency Switch Warning" confirm dialog
  // when manual token prices are missing for the target currency (feature added
  // in 4b65e5a). The test environment may or may not have such prices, so we
  // tolerate both paths: if the dialog appears we confirm; otherwise we proceed.
  async function confirmSwitchIfPrompted(page: import('@playwright/test').Page) {
    const dialog = page.getByRole('alertdialog').filter({ hasText: /Currency Switch Warning/i });
    try {
      await dialog.waitFor({ state: 'visible', timeout: 1500 });
      await dialog.getByRole('button', { name: /Switch Anyway/i }).click();
    } catch {
      // No conflict — direct switch path, nothing to confirm.
    }
  }

  test('changes currency to EUR via the dropdown', async ({ page }) => {
    await page.goto('/admin/compliance/config');
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    const selector = page.getByTestId('currency-selector');
    await expect(selector).toBeVisible({ timeout: 5000 });
    await expect(selector).toContainText('$ USD');

    // Open the currency dropdown
    await selector.click();

    // Wait for dropdown options to appear and click EUR
    const eurOption = page.getByRole('option', { name: /EUR/ });
    await expect(eurOption).toBeVisible({ timeout: 5000 });
    await eurOption.click();
    await confirmSwitchIfPrompted(page);

    // Verify the selector now shows EUR
    await expect(selector).toContainText('EUR', { timeout: 5000 });
  });

  test('currency change persists across page reload', async ({ page }) => {
    await page.goto('/admin/compliance/config');
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    const selector = page.getByTestId('currency-selector');
    await expect(selector).toBeVisible({ timeout: 5000 });

    // Change to EUR
    await selector.click();
    const eurOption = page.getByRole('option', { name: /EUR/ });
    await expect(eurOption).toBeVisible({ timeout: 5000 });
    await eurOption.click();
    await confirmSwitchIfPrompted(page);
    await expect(selector).toContainText('EUR', { timeout: 5000 });

    // Reload the page
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    // Verify EUR is still selected
    const selectorAfterReload = page.getByTestId('currency-selector');
    await expect(selectorAfterReload).toBeVisible({ timeout: 5000 });
    await expect(selectorAfterReload).toContainText('EUR', { timeout: 5000 });

    // Cleanup: change back to USD
    await selectorAfterReload.click();
    const usdOption = page.getByRole('option', { name: /USD/ });
    await expect(usdOption).toBeVisible({ timeout: 5000 });
    await usdOption.click();
    await confirmSwitchIfPrompted(page);
    await expect(selectorAfterReload).toContainText('$ USD', { timeout: 5000 });
  });

  test('currency selector is visible across compliance tabs', async ({ page }) => {
    // Start on config tab
    await page.goto('/admin/compliance/config');
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });
    await expect(page.getByTestId('currency-selector')).toBeVisible({ timeout: 5000 });

    // Navigate to sanctions tab (global tab)
    await page.getByRole('tab', { name: /Sanctions/ }).click();
    await expect(page.getByTestId('currency-selector')).toBeVisible({ timeout: 5000 });

    // Navigate to token prices tab
    await page.getByRole('tab', { name: /Token Prices/ }).click();
    await expect(page.getByTestId('currency-selector')).toBeVisible({ timeout: 5000 });
  });
});
