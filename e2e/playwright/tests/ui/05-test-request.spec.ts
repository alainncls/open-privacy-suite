import { test, expect } from '@playwright/test';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

test.describe('Test Request Panel', () => {
  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
    await page.goto('/admin/dashboard');
    // Wait for the Test Request panel to be visible
    await expect(page.getByRole('heading', { name: 'Test Request' })).toBeVisible({ timeout: 10000 });
  });

  // ── Rendering ──────────────────────────────────────────────────────

  test('panel displays with method dropdown and Send button', async ({ page }) => {
    await expect(page.getByRole('combobox')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Send' })).toBeVisible();
  });

  test('default method is eth_blockNumber', async ({ page }) => {
    const combobox = page.getByRole('combobox');
    await expect(combobox).toContainText('eth_blockNumber');
  });

  test('params textarea is visible for RPC methods', async ({ page }) => {
    await expect(page.getByText('Params (JSON array, optional)')).toBeVisible();
  });

  // ── Method dropdown ────────────────────────────────────────────────

  test('dropdown shows grouped options', async ({ page }) => {
    await page.getByRole('combobox').click();

    // Group labels
    await expect(page.getByText('RPC Methods')).toBeVisible();
    await expect(page.getByText('ERC20 Contract Calls')).toBeVisible();

    // A few representative RPC options
    await expect(page.getByRole('option', { name: 'eth_blockNumber' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'eth_chainId' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'net_version' })).toBeVisible();

    // A few representative ERC20 options
    await expect(page.getByRole('option', { name: 'ERC20 - balanceOf' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'ERC20 - totalSupply' })).toBeVisible();
  });

  test('selecting ERC20 - balanceOf shows contract address and owner fields', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - balanceOf' }).click();

    await expect(page.getByText('Contract Address')).toBeVisible();
    await expect(page.getByText('Owner')).toBeVisible();
    await expect(page.getByPlaceholder('Owner address (0x...)')).toBeVisible();

    // Params textarea should NOT be visible for ERC20 methods
    await expect(page.getByText('Params (JSON array, optional)')).not.toBeVisible();
  });

  test('selecting ERC20 - totalSupply shows only contract address', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - totalSupply' }).click();

    await expect(page.getByText('Contract Address')).toBeVisible();
    await expect(page.getByPlaceholder('0x...')).toBeVisible();

    // totalSupply has no extra fields (no owner, spender, etc.)
    await expect(page.getByText('Owner')).not.toBeVisible();
    await expect(page.getByText('Spender')).not.toBeVisible();
    await expect(page.getByText('Recipient')).not.toBeVisible();
    await expect(page.getByText('Amount')).not.toBeVisible();
  });

  test('selecting back to RPC method hides ERC20 fields', async ({ page }) => {
    // First select an ERC20 method
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - balanceOf' }).click();
    await expect(page.getByText('Contract Address')).toBeVisible();

    // Switch back to an RPC method
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'eth_blockNumber' }).click();

    // ERC20 fields should be gone, params textarea should return
    await expect(page.getByText('Contract Address')).not.toBeVisible();
    await expect(page.getByText('Params (JSON array, optional)')).toBeVisible();
  });

  // ── ERC20 form fields ─────────────────────────────────────────────

  test('ERC20 - allowance shows owner and spender fields', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - allowance' }).click();

    await expect(page.getByText('Contract Address')).toBeVisible();
    await expect(page.getByText('Owner')).toBeVisible();
    await expect(page.getByPlaceholder('Owner address (0x...)')).toBeVisible();
    await expect(page.getByText('Spender')).toBeVisible();
    await expect(page.getByPlaceholder('Spender address (0x...)')).toBeVisible();
  });

  test('ERC20 - transfer shows recipient and amount fields', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - transfer' }).click();

    await expect(page.getByText('Contract Address')).toBeVisible();
    await expect(page.getByText('Recipient')).toBeVisible();
    await expect(page.getByPlaceholder('Recipient address (0x...)')).toBeVisible();
    await expect(page.getByText('Amount')).toBeVisible();
    await expect(page.getByPlaceholder('Amount (in wei)')).toBeVisible();
  });

  test('ERC20 - approve shows spender and amount fields', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - approve' }).click();

    await expect(page.getByText('Contract Address')).toBeVisible();
    await expect(page.getByText('Spender')).toBeVisible();
    await expect(page.getByPlaceholder('Spender address (0x...)')).toBeVisible();
    await expect(page.getByText('Amount')).toBeVisible();
    await expect(page.getByPlaceholder('Amount (in wei)')).toBeVisible();
  });

  // ── Sending RPC requests ──────────────────────────────────────────

  test('sending eth_blockNumber returns 200 OK with result', async ({ page }) => {
    // Default method is eth_blockNumber, just click Send
    await page.getByRole('button', { name: 'Send' }).click();

    // Wait for the 200 OK badge to appear
    await expect(page.getByText('200 OK')).toBeVisible({ timeout: 10000 });

    // Should show a hex block number result (0x...)
    await expect(page.locator('pre')).toBeVisible();
    await expect(page.locator('pre')).toContainText('0x');

    // Should show latency
    await expect(page.getByText(/\d+ms/)).toBeVisible();

    // Should show the test:dashboard identity
    await expect(page.getByText(/Identity:.*test:dashboard/)).toBeVisible();
  });

  // ── JWT token section ─────────────────────────────────────────────

  test('clicking advanced section reveals JWT input', async ({ page }) => {
    // JWT section should be collapsed by default
    const advancedButton = page.getByRole('button', { name: 'Advanced: Test with JWT Token' });
    await expect(advancedButton).toBeVisible();

    // The JWT textarea should not be visible yet
    await expect(page.getByText('JWT Token')).not.toBeVisible();

    // Click to expand
    await advancedButton.click();

    // JWT textarea and label should appear
    await expect(page.getByText('JWT Token')).toBeVisible();
    await expect(page.getByPlaceholder('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')).toBeVisible();
    await expect(page.getByText(/Paste a JWT token to test as a specific user identity/)).toBeVisible();
  });

  // ── ERC20 validation ──────────────────────────────────────────────

  test('sending ERC20 without contract address shows error', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - totalSupply' }).click();

    // Leave contract address empty, click Send
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByText('Contract address is required')).toBeVisible();
  });

  test('sending ERC20 balanceOf without owner shows error', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - balanceOf' }).click();

    // Fill contract address but leave owner empty
    await page.getByPlaceholder('0x...').fill('0x' + '1'.repeat(40));
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByText('owner is required')).toBeVisible();
  });

  // ── Contract Info Panel ────────────────────────────────────────────

  test('entering valid contract address shows contract info panel or not-registered warning', async ({ page }) => {
    // Select an ERC20 method to show the contract address input
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - totalSupply' }).click();

    // Enter a random valid-format address (likely not registered)
    await page.getByPlaceholder('0x...').fill('0x' + 'a'.repeat(40));

    // Wait for debounce + lookup - should show either contract info or "not registered" warning
    await expect(page.getByTestId('contract-info-panel')).toBeVisible({ timeout: 10000 });
  });

  test('contract info panel disappears when address is cleared', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - totalSupply' }).click();

    // Enter a valid address
    await page.getByPlaceholder('0x...').fill('0x' + 'a'.repeat(40));
    await expect(page.getByTestId('contract-info-panel')).toBeVisible({ timeout: 10000 });

    // Clear the address
    await page.getByPlaceholder('0x...').fill('');

    // Panel should disappear
    await expect(page.getByTestId('contract-info-panel')).not.toBeVisible();
  });

  test('contract info panel shows not-registered for unknown address', async ({ page }) => {
    await page.getByRole('combobox').click();
    await page.getByRole('option', { name: 'ERC20 - totalSupply' }).click();

    // Enter a valid but unregistered address
    await page.getByPlaceholder('0x...').fill('0x' + 'f'.repeat(40));

    // Should show "Contract not registered" warning
    await expect(page.getByText('Contract not registered')).toBeVisible({ timeout: 10000 });
  });

  // ── User Context Panel ─────────────────────────────────────────────

  test('JWT section shows user info or not-found after pasting token', async ({ page }) => {
    // Expand advanced section
    await page.getByRole('button', { name: 'Advanced: Test with JWT Token' }).click();

    // Use a hardcoded JWT with sub: "did:test:unknown123", exp: 9999999999
    const fakeJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6dGVzdDp1bmtub3duMTIzIiwiZXhwIjo5OTk5OTk5OTk5fQ.fakesig';

    await page.getByPlaceholder('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...').fill(fakeJWT);

    // Should show either user context panel or "User not found" warning
    // Wait for debounce (500ms) + API call
    const panelOrWarning = page.getByText(/User not found|Looking up user/).first();
    await expect(panelOrWarning).toBeVisible({ timeout: 10000 });
  });
});
