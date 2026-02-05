import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

// Generate unique identifiers for test isolation
const generateOrgName = () => `Factory Test Org ${Date.now()}`;
const generateOrgSlug = () => `factory-test-${Date.now()}`;
// Salt prefix must be unique per test run to avoid "address already registered" errors
const generateSaltPrefix = (base: string) => `0x${base}${Date.now().toString(16).slice(-8)}`;

// Helper to check if runtime tracing is enabled (ABI column is hidden when enabled)
async function isRuntimeTracingEnabled(request: import('@playwright/test').APIRequestContext): Promise<boolean> {
  const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';
  try {
    const response = await request.get(`${ADMIN_URL}/api/v1/status`);
    if (response.ok()) {
      const data = await response.json();
      return data?.security?.runtime_tracing_enabled === true;
    }
  } catch {
    // If we can't check, assume it's disabled
  }
  return false;
}

test.describe('Pre-registered Addresses and Factory Config', () => {
  // Skip this entire test suite when runtime tracing is enabled
  // (preregistration is disabled when runtime tracing is enabled)
  test.beforeEach(async ({ page, request }) => {
    // Check if runtime tracing is enabled - if so, skip all tests in this suite
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }
    await mockLoginViaAPI(page);
  });

  test('preregistered addresses tab loads correctly', async ({ page }) => {
    // First create an org to work with
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    // Create organization
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Select the organization
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });
    await orgRow.click();

    // Navigate to Pre-registered tab
    await page.locator(selectors.rbac.tabPreregistered).click();

    // Tab should be active
    await expect(page.locator(selectors.rbac.tabPreregistered)).toHaveAttribute('data-state', 'active');

    // Should see "Pre-registered Addresses" heading (use role to avoid matching other text)
    await expect(page.getByRole('heading', { name: 'Pre-registered Addresses' })).toBeVisible();

    // Should see the description text
    await expect(page.getByText(/CREATE3 addresses whitelisted/i)).toBeVisible();

    // Add button should be visible
    await expect(page.getByRole('button', { name: /pre-register addresses/i })).toBeVisible();
  });

  test('shows empty state when no addresses preregistered', async ({ page }) => {
    // Create a fresh org with no preregistered addresses
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Select the organization
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });
    await orgRow.click();

    // Navigate to Pre-registered tab
    await page.locator(selectors.rbac.tabPreregistered).click();

    // Should see empty state
    await expect(page.getByText('No pre-registered addresses')).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: /pre-register your first addresses/i })).toBeVisible();
  });

  test('preregister dialog opens and shows form fields', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    // Create organization
    await page.getByRole('button', { name: /add organization/i }).click();
    let dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Select and navigate to preregistered
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });
    await orgRow.click();
    await page.locator(selectors.rbac.tabPreregistered).click();

    // Open preregister dialog
    await page.getByRole('button', { name: /pre-register addresses/i }).click();

    // Dialog should appear
    dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await expect(dialog.getByText('Pre-register CREATE3 Addresses')).toBeVisible();

    // Form fields should be present (either directly or after factory is configured)
    // In dev mode, might show factory deployment option first
    const hasDeployButton = await dialog.getByRole('button', { name: /deploy create3 factory/i }).isVisible().catch(() => false);
    const hasFactoryField = await dialog.getByLabel(/factory address/i).isVisible().catch(() => false);

    // Either deployment option or factory field should be visible
    expect(hasDeployButton || hasFactoryField).toBe(true);

    // Cancel button should be present
    await expect(dialog.getByRole('button', { name: /cancel/i })).toBeVisible();
  });

  test('can close preregister dialog with cancel', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    // Create organization
    await page.getByRole('button', { name: /add organization/i }).click();
    let dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Select and navigate to preregistered
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });
    await orgRow.click();
    await page.locator(selectors.rbac.tabPreregistered).click();

    // Open dialog
    await page.getByRole('button', { name: /pre-register addresses/i }).click();
    dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 10000 });

    // Cancel
    await dialog.getByRole('button', { name: /cancel/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible();
  });

  test('different orgs show independent factory configurations', async ({ page, request }) => {
    // Create two organizations via API to set up controlled test data
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const org1Slug = `factory-test-1-${Date.now()}`;
    const org2Slug = `factory-test-2-${Date.now()}`;
    const factory1 = '0x' + '1'.repeat(40);
    const factory2 = '0x' + '2'.repeat(40);

    // Create org1 via API
    const org1Response = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: org1Slug, name: `Test Org 1 ${Date.now()}` },
    });
    expect(org1Response.ok()).toBe(true);
    const org1 = await org1Response.json();

    // Create org2 via API
    const org2Response = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: org2Slug, name: `Test Org 2 ${Date.now()}` },
    });
    expect(org2Response.ok()).toBe(true);
    const org2 = await org2Response.json();

    // Set different factories for each org
    const config1Response = await request.put(`${ADMIN_URL}/api/orgs/${org1.id}/config/create3`, {
      headers: { 'Content-Type': 'application/json' },
      data: { factory: factory1 },
    });
    expect(config1Response.ok()).toBe(true);

    const config2Response = await request.put(`${ADMIN_URL}/api/orgs/${org2.id}/config/create3`, {
      headers: { 'Content-Type': 'application/json' },
      data: { factory: factory2 },
    });
    expect(config2Response.ok()).toBe(true);

    // Navigate to org1's preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org1.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for loading to complete and check for factory1
    await page.waitForTimeout(1000); // Allow data to load
    const factory1Display = page.getByText(factory1.toLowerCase());
    await expect(factory1Display).toBeVisible({ timeout: 5000 });

    // Now switch to org2
    const orgSelector = page.locator(selectors.rbac.orgSelector);
    await orgSelector.click();
    await page.getByText(org2Slug).click();

    // Wait for factory2 to be displayed
    await page.waitForTimeout(1000);
    const factory2Display = page.getByText(factory2.toLowerCase());
    await expect(factory2Display).toBeVisible({ timeout: 5000 });

    // factory1 should not be visible when viewing org2
    await expect(factory1Display).not.toBeVisible();
  });

  test('factory address displays with copy button', async ({ page, request }) => {
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `factory-copy-test-${Date.now()}`;
    const factory = '0x' + 'abcd'.repeat(10);

    // Create org and set factory via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `Copy Test Org ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    await request.put(`${ADMIN_URL}/api/orgs/${org.id}/config/create3`, {
      headers: { 'Content-Type': 'application/json' },
      data: { factory },
    });

    // Navigate to the org's preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for factory display
    await page.waitForTimeout(1000);

    // Factory section should be visible
    const factorySection = page.locator('text=CREATE3 Factory').first();
    await expect(factorySection).toBeVisible({ timeout: 5000 });

    // Copy button should be present next to factory address
    const copyButton = page.getByTitle('Copy factory address').first();
    await expect(copyButton).toBeVisible();
  });

  test('preregistered addresses table shows correct columns', async ({ page, request }) => {
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `table-test-${Date.now()}`;
    const factory = '0x' + 'ef'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `Table Test Org ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister some addresses
    const preregResponse = await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('test'),
        count: 2,
        note: 'Test addresses',
      },
    });
    expect(preregResponse.ok()).toBe(true);

    // Navigate to the org's preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // Table should be visible
    const table = page.getByRole('table');
    await expect(table).toBeVisible({ timeout: 5000 });

    // Check for expected column headers
    await expect(page.getByRole('columnheader', { name: /address/i })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /factory/i })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /salt/i })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /note/i })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /status/i })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /created/i })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /actions/i })).toBeVisible();
  });

  test('preregistered address row has copy buttons', async ({ page, request }) => {
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `copy-buttons-test-${Date.now()}`;
    const factory = '0x' + '99'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `Copy Buttons Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    const preregResponse = await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('copy'),
        count: 1,
      },
    });
    expect(preregResponse.ok()).toBe(true);

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // Should see copy buttons (for address, factory, salt)
    const copyButtons = page.getByTitle(/copy/i);
    // At least 3 copy buttons should exist (address, factory, salt) + factory header
    await expect(copyButtons.first()).toBeVisible({ timeout: 5000 });
    const count = await copyButtons.count();
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('pending status badge shown for unused addresses', async ({ page, request }) => {
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `status-test-${Date.now()}`;
    const factory = '0x' + 'bb'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `Status Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address (it will be unused/pending)
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('status'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table
    await page.waitForTimeout(1000);

    // Should see "Pending" status badge
    const pendingBadge = page.getByText('Pending');
    await expect(pendingBadge).toBeVisible({ timeout: 5000 });
  });

  test('delete button exists for preregistered addresses', async ({ page, request }) => {
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `delete-test-${Date.now()}`;
    const factory = '0x' + 'cc'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `Delete Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('delete'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table
    await page.waitForTimeout(1000);

    // Delete button should be visible
    const deleteButton = page.getByTitle('Delete pre-registered address');
    await expect(deleteButton).toBeVisible({ timeout: 5000 });
  });

  test('can delete a preregistered address', async ({ page, request }) => {
    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `delete-confirm-test-${Date.now()}`;
    const factory = '0x' + 'dd'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `Delete Confirm Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    const preregResponse = await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('delconfirm'),
        count: 1,
      },
    });
    expect(preregResponse.ok()).toBe(true);
    const preregData = await preregResponse.json();
    const addressToDelete = preregData.addresses[0].address;

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table and verify address is shown
    await page.waitForTimeout(1000);
    const truncatedAddr = addressToDelete.slice(0, 8) + '...' + addressToDelete.slice(-6);
    await expect(page.getByText(truncatedAddr)).toBeVisible({ timeout: 5000 });

    // Click delete button
    await page.getByTitle('Delete pre-registered address').click();

    // Confirmation dialog should appear
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });
    await expect(dialog.getByText('Delete Pre-registered Address')).toBeVisible();

    // Confirm deletion
    await dialog.getByRole('button', { name: /delete/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 5000 });

    // Address should no longer be in the list
    await page.waitForTimeout(500);
    await expect(page.getByText(truncatedAddr)).not.toBeVisible();
  });

  test('ABI column visible in table', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-column-test-${Date.now()}`;
    const factory = '0x' + 'aa'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Column Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('abicol'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // ABI column header should be visible
    await expect(page.getByRole('columnheader', { name: /abi/i })).toBeVisible({ timeout: 5000 });
  });

  test('shows "Not set" badge when no ABI configured', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-notset-test-${Date.now()}`;
    const factory = '0x' + 'ab'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Badge Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address WITHOUT ABI
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('noabi'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // "Not set" badge should be visible in the table (use exact match to avoid matching org name)
    const table = page.getByRole('table');
    await expect(table.getByText('Not set', { exact: true })).toBeVisible({ timeout: 5000 });
  });

  test('can open ABI editor modal', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-editor-open-test-${Date.now()}`;
    const factory = '0x' + 'ac'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Editor Open Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    const preregResponse = await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('abieditor'),
        count: 1,
      },
    });
    expect(preregResponse.ok()).toBe(true);
    const preregData = await preregResponse.json();
    const address = preregData.addresses[0].address;

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // Click the pencil button to edit ABI
    await page.getByTitle('Edit contract ABI').click();

    // Dialog should appear
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Dialog should show correct title
    await expect(dialog.getByText('Edit Constructor ABI')).toBeVisible();

    // Dialog should show the address
    await expect(dialog.getByText(address)).toBeVisible();

    // Textarea should be visible
    await expect(dialog.locator('textarea')).toBeVisible();

    // Save and Cancel buttons should be visible
    await expect(dialog.getByRole('button', { name: /save abi/i })).toBeVisible();
    await expect(dialog.getByRole('button', { name: /cancel/i })).toBeVisible();
  });

  test('can save ABI successfully', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-save-test-${Date.now()}`;
    const factory = '0x' + 'ad'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Save Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('abisave'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table and verify "Not set" badge is shown initially
    await page.waitForTimeout(1000);
    const table = page.getByRole('table');
    await expect(table.getByText('Not set', { exact: true })).toBeVisible({ timeout: 5000 });

    // Click the pencil button to edit ABI
    await page.getByTitle('Edit contract ABI').click();

    // Dialog should appear
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Enter valid ABI JSON
    const validABI = '[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]';
    await dialog.locator('textarea').fill(validABI);

    // Click Save ABI
    await dialog.getByRole('button', { name: /save abi/i }).click();

    // Dialog should close (give more time for API call)
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Badge should now show "Set" instead of "Not set" in the table
    await page.waitForTimeout(500); // Allow UI to refresh
    await expect(table.getByText('Set', { exact: true })).toBeVisible({ timeout: 5000 });
    // "Not set" should no longer be visible for this address
    await expect(table.getByText('Not set', { exact: true })).not.toBeVisible();
  });

  test('shows JSON validation error for invalid ABI', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-validation-test-${Date.now()}`;
    const factory = '0x' + 'ae'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Validation Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('abivalidate'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // Click the pencil button to edit ABI
    await page.getByTitle('Edit contract ABI').click();

    // Dialog should appear
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Enter invalid JSON
    await dialog.locator('textarea').fill('not valid json');

    // Click Save ABI
    await dialog.getByRole('button', { name: /save abi/i }).click();

    // Should show validation error
    await expect(dialog.getByText('Invalid JSON format')).toBeVisible({ timeout: 5000 });

    // Dialog should still be open
    await expect(dialog).toBeVisible();
  });

  test('can close ABI editor with cancel', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-cancel-test-${Date.now()}`;
    const factory = '0x' + 'af'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Cancel Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('abicancel'),
        count: 1,
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // Click the pencil button to edit ABI
    await page.getByTitle('Edit contract ABI').click();

    // Dialog should appear
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Click Cancel
    await dialog.getByRole('button', { name: /cancel/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 5000 });

    // "Not set" should still be shown in the table (ABI not changed)
    const table = page.getByRole('table');
    await expect(table.getByText('Not set', { exact: true })).toBeVisible();
  });

  test('shows "Set" badge for address with ABI pre-configured', async ({ page, request }) => {
    // Skip this test if runtime tracing is enabled (ABI column is hidden)
    if (await isRuntimeTracingEnabled(request)) {
      test.skip();
      return;
    }

    const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

    const orgSlug = `abi-preset-test-${Date.now()}`;
    const factory = '0x' + 'ba'.repeat(20);

    // Create org via API
    const orgResponse = await request.post(`${ADMIN_URL}/api/orgs`, {
      headers: { 'Content-Type': 'application/json' },
      data: { slug: orgSlug, name: `ABI Preset Test ${Date.now()}` },
    });
    expect(orgResponse.ok()).toBe(true);
    const org = await orgResponse.json();

    // Preregister an address WITH ABI
    await request.post(`${ADMIN_URL}/api/orgs/${org.id}/addresses/preregister`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        factory,
        salt_prefix: generateSaltPrefix('abipreset'),
        count: 1,
        constructor_abi: '[{"type":"constructor","inputs":[{"name":"admin","type":"address"}]}]',
      },
    });

    // Navigate to preregistered tab
    await page.goto(`/admin/rbac/preregistered?org=${org.id}`);
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Wait for table to load
    await page.waitForTimeout(1000);

    // "Set" badge should be visible in the table (not "Not set")
    const table = page.getByRole('table');
    await expect(table.getByText('Set', { exact: true })).toBeVisible({ timeout: 5000 });
    await expect(table.getByText('Not set', { exact: true })).not.toBeVisible();
  });
});
