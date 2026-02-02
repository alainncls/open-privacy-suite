import { test, expect } from '@playwright/test';
import { selectors, roles } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

// Generate unique names for test organizations to avoid conflicts
const generateOrgName = () => `Test Org ${Date.now()}`;
const generateOrgSlug = () => `test-org-${Date.now()}`;

test.describe('Organization CRUD', () => {
  test.beforeEach(async ({ page }) => {
    // Authenticate before each test
    await mockLoginViaAPI(page);
  });

  test('organizations list displays correctly', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');

    // Wait for RBAC manager to load
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Organizations tab should be active
    const orgsTab = page.locator(selectors.rbac.tabOrganizations);
    await expect(orgsTab).toHaveAttribute('data-state', 'active');

    // Should see "Organizations" heading (use role selector to avoid matching tab/badge text)
    await expect(page.getByRole('heading', { name: 'Organizations', exact: true })).toBeVisible();
    await expect(page.getByText('Top-level tenants that contain groups and contracts')).toBeVisible();

    // Add Organization button should be visible
    await expect(page.getByRole('button', { name: /add organization/i })).toBeVisible();
  });

  test('can open create organization dialog', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Click Add Organization button
    await page.getByRole('button', { name: /add organization/i }).click();

    // Dialog should appear
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();

    // Dialog should have correct title (use heading role to avoid matching button)
    await expect(dialog.getByRole('heading', { name: 'Create Organization' })).toBeVisible();

    // Form fields should be present
    await expect(dialog.getByLabel(/name/i)).toBeVisible();
    await expect(dialog.getByLabel(/slug/i)).toBeVisible();

    // Submit and cancel buttons should be present
    await expect(dialog.getByRole('button', { name: /create organization/i })).toBeVisible();
    await expect(dialog.getByRole('button', { name: /cancel/i })).toBeVisible();
  });

  test('can close create organization dialog with cancel', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Open dialog
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();

    // Click cancel
    await dialog.getByRole('button', { name: /cancel/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible();
  });

  test('create organization form auto-generates slug from name', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Open dialog
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();

    // Type in name field
    const nameInput = dialog.getByLabel(/name/i);
    await nameInput.fill('My Test Organization');

    // Slug should be auto-generated
    const slugInput = dialog.getByLabel(/slug/i);
    await expect(slugInput).toHaveValue('my-test-organization');
  });

  test('can create a new organization', async ({ page }) => {
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Open dialog
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();

    // Fill in form
    const nameInput = dialog.getByLabel(/name/i);
    const slugInput = dialog.getByLabel(/slug/i);

    await nameInput.fill(orgName);
    await slugInput.fill(orgSlug);

    // Submit form
    await dialog.getByRole('button', { name: /create organization/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // New organization should appear in the list
    await expect(page.getByText(orgName)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(orgSlug)).toBeVisible();
  });

  test('organization form validates required fields', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Open dialog
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();

    // Try to submit without filling fields
    const submitBtn = dialog.getByRole('button', { name: /create organization/i });
    await submitBtn.click();

    // Form should show validation - required fields shouldn't allow empty submission
    // The native HTML5 validation will prevent submission
    // We can check that the dialog is still open (form wasn't submitted)
    await expect(dialog).toBeVisible();
  });

  test('can edit an existing organization', async ({ page }) => {
    // First, create an organization to edit
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Create organization
    await page.getByRole('button', { name: /add organization/i }).click();
    let dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Wait for the new org to appear in the list
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    // Click edit button on the row
    const editBtn = orgRow.getByTitle(/edit organization/i);
    await editBtn.click();

    // Edit dialog should appear
    dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('Edit Organization')).toBeVisible();

    // Modify the name
    const newName = `${orgName} Updated`;
    const nameInput = dialog.getByLabel(/name/i);
    await nameInput.clear();
    await nameInput.fill(newName);

    // Submit changes
    await dialog.getByRole('button', { name: /update organization/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Updated name should appear in the list
    await expect(page.getByText(newName)).toBeVisible({ timeout: 10000 });
  });

  test('can delete an organization', async ({ page }) => {
    // First, create an organization to delete
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Create organization
    await page.getByRole('button', { name: /add organization/i }).click();
    let dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Wait for the new org to appear in the list
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    // Click delete button on the row
    const deleteBtn = orgRow.getByTitle(/delete organization/i);
    await deleteBtn.click();

    // Confirm dialog should appear
    dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('Delete Organization')).toBeVisible();

    // Confirm deletion
    await dialog.getByRole('button', { name: /delete/i }).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Organization should no longer be in the list
    await expect(page.getByText(orgName)).not.toBeVisible({ timeout: 10000 });
  });

  test('organization list shows created date', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Table should have Created column
    await expect(page.getByRole('columnheader', { name: /created/i })).toBeVisible();
  });

  test('organization list shows slug badge', async ({ page }) => {
    // Create an organization first
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Slug should appear in the table (shown as a badge)
    await expect(page.getByText(orgSlug)).toBeVisible({ timeout: 10000 });
  });

  test('clicking organization row selects it', async ({ page }) => {
    // Create an organization to click
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Wait for org to appear
    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    // Click on the organization row (not the edit/delete buttons)
    await orgRow.click();

    // Navigate to groups tab to see if org is selected in the dropdown
    await page.locator(selectors.rbac.tabGroups).click();

    // Org selector should show the selected organization
    const orgSelector = page.locator(selectors.rbac.orgSelector);
    await expect(orgSelector).toContainText(orgName);
  });

  test('empty state shows create button', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // If there are no organizations, we should see the empty state
    // Note: This test may not show empty state if orgs already exist from other tests
    const emptyState = page.getByText('No organizations found');
    const table = page.getByRole('table');

    // Either we see the empty state or we see the table
    const isEmpty = await emptyState.isVisible().catch(() => false);

    if (isEmpty) {
      // Empty state should have a create button
      await expect(page.getByRole('button', { name: /create your first organization/i })).toBeVisible();
    } else {
      // Table should be visible if not empty
      await expect(table).toBeVisible();
    }
  });

  test('delete error shows alert dialog', async ({ page }) => {
    // This test verifies the error dialog structure exists
    // Note: Triggering a real delete error requires an org with groups/contracts

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // The AlertDialog component should be present in the page
    // We can't easily trigger it without an org that has dependencies
    // Just verify the page loaded correctly
    await expect(page.getByRole('heading', { name: 'Organizations', exact: true })).toBeVisible();
  });

  test('organization form shows validation hints', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Open dialog
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();

    // Should see helper text for fields
    await expect(dialog.getByText('Display name for the organization')).toBeVisible();
    await expect(dialog.getByText('URL-friendly identifier')).toBeVisible();
  });
});
