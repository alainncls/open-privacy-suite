import { test, expect } from '@playwright/test';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

const TEST_TOKEN_ADDRESS = '0xe2ee2ee2ee2ee2ee2ee2ee2ee2ee2ee2ee2ee2ee';
const TEST_SYMBOL = 'E2ETEST';
const TEST_DECIMALS = 18;
const INITIAL_PRICE = 123.45;
const UPDATED_PRICE = 678.90;

test.describe.serial('External Rates UI', () => {
  let apiKey: string;
  let apiKeyId: string;

  test.beforeAll(async ({ request }) => {
    // Disable cooldown and set permissive bounds for E2E tests
    await request.put(`${ADMIN_URL}/api/v1/admin/compliance/external-rates-settings`, {
      data: { price_update_cooldown_minutes: 0, max_price_deviation_pct: 500 },
    });

    // Create an API key for pushing external prices
    const keyResponse = await request.post(`${ADMIN_URL}/api/v1/admin/compliance/api-keys`, {
      data: { name: 'E2E UI Rates Test Key' },
    });
    expect(keyResponse.status()).toBe(201);

    const keyBody = await keyResponse.json();
    apiKey = keyBody.key;
    apiKeyId = keyBody.id;

    // Push a test token price via the external API
    const rateResponse = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        token_address: TEST_TOKEN_ADDRESS,
        price: INITIAL_PRICE,
        symbol: TEST_SYMBOL,
        decimals: TEST_DECIMALS,
      },
    });
    expect(rateResponse.status()).toBe(201);
  });

  test.afterAll(async ({ request }) => {
    if (apiKeyId) {
      await request.delete(`${ADMIN_URL}/api/v1/admin/compliance/api-keys/${apiKeyId}`);
    }
    // System token prices cannot be deleted via API; E2E environment is ephemeral.
  });

  test('external token appears in system prices section', async ({ page }) => {
    await mockLoginViaAPI(page);
    await page.goto('/admin/compliance/tokens');

    // Wait for the system prices section to load
    await expect(
      page.getByText('Auto-Fetched Prices', { exact: false })
    ).toBeVisible({ timeout: 15000 });

    // Find the system prices grid
    const grid = page.locator('.grid.grid-cols-1');

    // Find a card containing our test symbol
    const card = grid.locator('div').filter({ hasText: TEST_SYMBOL }).first();
    await expect(card).toBeVisible({ timeout: 10000 });

    // Verify the "external" source badge is visible within the card
    await expect(card.locator('text=external')).toBeVisible();

    // Verify the price is displayed (look for a formatted number in the card)
    await expect(card.locator('.text-xl.font-semibold')).not.toHaveText('—');
  });

  test('updated price reflects in UI after reload', async ({ page, request }) => {
    // Push a new price for the same token
    const updateResponse = await request.put(`${ADMIN_URL}/api/v1/external/rates`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      data: {
        token_address: TEST_TOKEN_ADDRESS,
        price: UPDATED_PRICE,
      },
    });
    expect(updateResponse.status()).toBe(200);

    // Login and navigate
    await mockLoginViaAPI(page);
    await page.goto('/admin/compliance/tokens');

    // Wait for the system prices section
    await expect(
      page.getByText('Auto-Fetched Prices', { exact: false })
    ).toBeVisible({ timeout: 15000 });

    // Find our test token card
    const grid = page.locator('.grid.grid-cols-1');
    const card = grid.locator('div').filter({ hasText: TEST_SYMBOL }).first();
    await expect(card).toBeVisible({ timeout: 10000 });

    // Verify the updated price is shown (formatted as currency, e.g., "$678.90")
    const priceEl = card.locator('.text-xl.font-semibold');
    await expect(priceEl).toContainText('678.9');
  });

  test('system prices show source badges', async ({ page }) => {
    await mockLoginViaAPI(page);
    await page.goto('/admin/compliance/tokens');

    // Wait for the system prices section
    await expect(
      page.getByText('Auto-Fetched Prices', { exact: false })
    ).toBeVisible({ timeout: 15000 });

    // All system price cards should have a source badge (either "coingecko" or "external")
    const grid = page.locator('.grid.grid-cols-1');
    const cards = grid.locator('> div');

    const cardCount = await cards.count();
    expect(cardCount).toBeGreaterThanOrEqual(1);

    // Check that at least one card has a recognizable source badge
    const hasSourceBadge = await grid.locator('text=/coingecko|external/').count();
    expect(hasSourceBadge).toBeGreaterThanOrEqual(1);
  });
});
