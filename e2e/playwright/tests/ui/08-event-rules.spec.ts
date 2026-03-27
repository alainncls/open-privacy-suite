import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

// Minimal ERC20 ABI with Transfer and Approval events + a transfer function.
// The backend parses this to extract event signatures for the event picker.
const ERC20_ABI = JSON.stringify([
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: 'from', type: 'address' },
      { indexed: true, name: 'to', type: 'address' },
      { indexed: false, name: 'value', type: 'uint256' },
    ],
    name: 'Transfer',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: 'owner', type: 'address' },
      { indexed: true, name: 'spender', type: 'address' },
      { indexed: false, name: 'value', type: 'uint256' },
    ],
    name: 'Approval',
    type: 'event',
  },
  {
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', type: 'bool' }],
    type: 'function',
    stateMutability: 'nonpayable',
  },
  {
    inputs: [{ name: 'account', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', type: 'uint256' }],
    type: 'function',
    stateMutability: 'view',
  },
]);

// ---------------------------------------------------------------------------
// Helper: open the Contract Permissions dialog for the first contract in the
// table, then click "Add Group" to open the grant form.
// Returns the grant form dialog locator.
// ---------------------------------------------------------------------------
async function openGrantForm(page: import('@playwright/test').Page) {
  // Click the shield icon on the first contract row to open the permissions dialog
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(1, { timeout: 10000 });
  const shieldBtn = rows.first().getByTitle('Manage permissions');
  await shieldBtn.click();

  // Wait for the "Contract Permissions" dialog
  const permDialog = page.locator(selectors.common.dialog);
  await expect(permDialog).toBeVisible({ timeout: 5000 });
  await expect(permDialog.getByText('Contract Permissions')).toBeVisible();

  // Click "Add Group" to open the grant form
  await permDialog.getByRole('button', { name: /add group/i }).click();

  // A nested dialog appears — use the "Add Group Access" title to scope
  const grantDialog = page.locator(selectors.common.dialog).filter({ hasText: 'Add Group Access' });
  await expect(grantDialog).toBeVisible({ timeout: 5000 });
  return grantDialog;
}

// ---------------------------------------------------------------------------
// Helper: open the edit form for the first grant on the first contract.
// ---------------------------------------------------------------------------
async function openEditGrantForm(page: import('@playwright/test').Page) {
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(1, { timeout: 10000 });
  const shieldBtn = rows.first().getByTitle('Manage permissions');
  await shieldBtn.click();

  const permDialog = page.locator(selectors.common.dialog);
  await expect(permDialog).toBeVisible({ timeout: 5000 });
  await expect(permDialog.getByText('Contract Permissions')).toBeVisible();

  // Click the edit (pencil) button on the first grant card
  const editBtn = permDialog.getByTitle('Edit function access').first();
  await editBtn.click();

  // The edit dialog has "Edit Grant Rules" title
  const editDialog = page.locator(selectors.common.dialog).filter({ hasText: 'Edit Grant Rules' });
  await expect(editDialog).toBeVisible({ timeout: 5000 });
  return editDialog;
}

// ---------------------------------------------------------------------------
// Group A: Default state and mode switching
// ---------------------------------------------------------------------------

test.describe('Event rules — default state and mode switching', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('A1: grant form defaults to "All events visible"', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-a1');
    const group = await fixture.createGroup(org.id, 'grp-a1', { name: 'Group A1' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token A1',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // "All events visible" radio should be checked by default
    const allEventsRadio = grantDialog.locator('input[name="eventMode"][value="all"]');
    await expect(allEventsRadio).toBeChecked();

    // The event picker should NOT be visible in "all" mode
    await expect(grantDialog.getByText('Visible events:')).not.toBeVisible();
    await expect(grantDialog.getByText('Contract events')).not.toBeVisible();
  });

  test('A2: switching to "Specific events only" shows event picker', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-a2');
    const group = await fixture.createGroup(org.id, 'grp-a2', { name: 'Group A2' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token A2',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Click "Specific events only" radio
    await grantDialog.getByText('Specific events only').click();

    const specificRadio = grantDialog.locator('input[name="eventMode"][value="specific"]');
    await expect(specificRadio).toBeChecked();

    // Event picker should now be visible with 2 events from the ERC20 ABI
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Both events should appear in the picker
    await expect(grantDialog.getByRole('button', { name: /Transfer/ })).toBeVisible();
    await expect(grantDialog.getByRole('button', { name: /Approval/ })).toBeVisible();
  });

  test('A3: switching back to "All events visible" hides event picker', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-a3');
    const group = await fixture.createGroup(org.id, 'grp-a3', { name: 'Group A3' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token A3',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Switch back to all
    await grantDialog.getByText('All events visible').click();

    const allRadio = grantDialog.locator('input[name="eventMode"][value="all"]');
    await expect(allRadio).toBeChecked();

    // Event picker should be hidden again
    await expect(grantDialog.getByText('Contract events (2):')).not.toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group B: Selecting events and adding param constraints
// ---------------------------------------------------------------------------

test.describe('Event rules — selecting events and constraints', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('B1: selecting events from the picker adds them to the visible list', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-b1');
    await fixture.createGroup(org.id, 'grp-b1', { name: 'Group B1' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token B1',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Click Transfer event in the picker
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();

    // "Visible events:" section should appear with Transfer listed
    await expect(grantDialog.getByText('Visible events:')).toBeVisible();
    // The selected event should show in a pill/card containing the event name
    const visibleSection = grantDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer')).toBeVisible();

    // The Transfer button in the picker should now be disabled (already selected)
    const transferPickerBtn = grantDialog.locator('button').filter({ hasText: 'Transfer' }).last();
    await expect(transferPickerBtn).toBeDisabled();
  });

  test('B2: removing a selected event re-enables it in the picker', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-b2');
    await fixture.createGroup(org.id, 'grp-b2', { name: 'Group B2' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token B2',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Add Transfer
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();
    await expect(grantDialog.getByText('Visible events:')).toBeVisible();

    // Remove Transfer by clicking the X button on the selected event pill
    const selectedEvent = grantDialog.locator('.border.border-primary-50').filter({ hasText: 'Transfer' });
    await selectedEvent.locator('button').click();

    // "Visible events:" header should disappear (no events selected)
    await expect(grantDialog.getByText('Visible events:')).not.toBeVisible();
  });

  test('B3: address param constraint checkbox appears for events with address inputs', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-b3');
    await fixture.createGroup(org.id, 'grp-b3', { name: 'Group B3' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token B3',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events and add Transfer
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();

    // Transfer has address params (from, to) — should show "must be caller's own address" checkboxes
    const selectedEvent = grantDialog.locator('.border.border-primary-50').filter({ hasText: 'Transfer' });
    await expect(selectedEvent.getByText(/must be caller.*address/i)).toBeVisible();

    // Specifically, 'from' and 'to' params should be listed
    await expect(selectedEvent.getByText('from')).toBeVisible();
    await expect(selectedEvent.getByText('to')).toBeVisible();
  });

  test('B4: checking a param constraint checkbox adds a param_rule', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-b4');
    const group = await fixture.createGroup(org.id, 'grp-b4', { name: 'Group B4' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token B4',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Select the group
    await grantDialog.locator('select').selectOption(group.id);

    // Switch to specific events and add Transfer
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();

    // Check the 'from' param constraint
    const selectedEvent = grantDialog.locator('.border.border-primary-50').filter({ hasText: 'Transfer' });
    const fromCheckbox = selectedEvent.locator('label').filter({ hasText: 'from' }).locator('input[type="checkbox"]');
    await fromCheckbox.check();
    await expect(fromCheckbox).toBeChecked();

    // The param rule badge should appear
    await expect(selectedEvent.getByText('param[0]=self')).toBeVisible();

    // Save the grant
    await grantDialog.getByRole('button', { name: /add group access/i }).click();

    // Dialog should close
    await expect(grantDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API that the grant has the event rule with param constraint
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeTruthy();
    expect(savedGrant!.event_rules!.length).toBe(1);
    expect(savedGrant!.event_rules![0].name).toBe('Transfer');
    expect(savedGrant!.event_rules![0].param_rules).toBeTruthy();
    expect(savedGrant!.event_rules![0].param_rules!.length).toBe(1);
    expect(savedGrant!.event_rules![0].param_rules![0]).toEqual({ index: 0, must_be: 'self' });
  });
});

// ---------------------------------------------------------------------------
// Group C: Saving and displaying grants with event rules
// ---------------------------------------------------------------------------

test.describe('Event rules — save and display', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('C1: save grant with specific events, verify display as pills', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-c1');
    const group = await fixture.createGroup(org.id, 'grp-c1', { name: 'Group C1' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token C1',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Select group
    await grantDialog.locator('select').selectOption(group.id);

    // Switch to specific events, add both Transfer and Approval
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();
    await grantDialog.getByRole('button', { name: /Approval/ }).click();

    // Save
    await grantDialog.getByRole('button', { name: /add group access/i }).click();
    await expect(grantDialog).not.toBeVisible({ timeout: 10000 });

    // The permissions dialog should now show the grant card with event pills
    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible();

    // Should show "Events:" label with event name pills (violet-colored)
    await expect(permDialog.getByText('Events:')).toBeVisible();
    // Event pills use violet-100 background and contain event names
    const eventPills = permDialog.locator('.bg-violet-100');
    await expect(eventPills).toHaveCount(2);
    await expect(permDialog.locator('.bg-violet-100').filter({ hasText: 'Transfer' })).toBeVisible();
    await expect(permDialog.locator('.bg-violet-100').filter({ hasText: 'Approval' })).toBeVisible();
  });

  test('C2: grant with "All events" shows "All events visible" in display', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-c2');
    const group = await fixture.createGroup(org.id, 'grp-c2', { name: 'Group C2' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token C2',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Select group
    await grantDialog.locator('select').selectOption(group.id);

    // Leave event mode as "All events visible" (the default)
    // Save
    await grantDialog.getByRole('button', { name: /add group access/i }).click();
    await expect(grantDialog).not.toBeVisible({ timeout: 10000 });

    // Should show "All events visible" in the grant card
    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible();
    await expect(permDialog.getByText('All events visible')).toBeVisible();

    // Verify via API: event_rules should be null
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeNull();
  });

  test('C3: validation error when specific mode selected but no events added', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-c3');
    const group = await fixture.createGroup(org.id, 'grp-c3', { name: 'Group C3' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    await fixture.createContractWithABI(org.id, {
      name: 'Token C3',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Select group
    await grantDialog.locator('select').selectOption(group.id);

    // Switch to specific events but do NOT add any events
    await grantDialog.getByText('Specific events only').click();

    // Try to save
    await grantDialog.getByRole('button', { name: /add group access/i }).click();

    // Should show validation error
    await expect(grantDialog.getByText(/please add at least one event/i)).toBeVisible({ timeout: 5000 });

    // Dialog should still be open
    await expect(grantDialog).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group D: Editing existing grants
// ---------------------------------------------------------------------------

test.describe('Event rules — editing existing grants', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('D1: edit form pre-populates existing event rules', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-d1');
    const group = await fixture.createGroup(org.id, 'grp-d1', { name: 'Group D1' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token D1',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API to get real topic0 values
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');
    expect(transferEvent).toBeTruthy();

    // Create grant with a specific event rule via API
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Open the edit form for the existing grant
    const editDialog = await openEditGrantForm(page);

    // "Specific events only" radio should be pre-selected
    const specificRadio = editDialog.locator('input[name="eventMode"][value="specific"]');
    await expect(specificRadio).toBeChecked();

    // Transfer should appear in the "Visible events:" section
    await expect(editDialog.getByText('Visible events:')).toBeVisible();
    const visibleSection = editDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer')).toBeVisible();
  });

  test('D2: edit grant to add more events', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-d2');
    const group = await fixture.createGroup(org.id, 'grp-d2', { name: 'Group D2' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token D2',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API to get real topic0 values
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');
    expect(transferEvent).toBeTruthy();

    // Create grant with only Transfer
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const editDialog = await openEditGrantForm(page);

    // Transfer should already be selected. Add Approval.
    await expect(editDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await editDialog.getByRole('button', { name: /Approval/ }).click();

    // Both should now be in the visible list
    const visibleSection = editDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer')).toBeVisible();
    await expect(visibleSection.getByText('Approval')).toBeVisible();

    // Save
    await editDialog.getByRole('button', { name: /save changes/i }).click();
    await expect(editDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeTruthy();
    expect(savedGrant!.event_rules!.length).toBe(2);
    const ruleNames = savedGrant!.event_rules!.map(r => r.name).sort();
    expect(ruleNames).toEqual(['Approval', 'Transfer']);
  });

  test('D3: edit grant to switch from specific events back to all events', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-d3');
    const group = await fixture.createGroup(org.id, 'grp-d3', { name: 'Group D3' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['read'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token D3',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');

    // Create grant with specific event
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const editDialog = await openEditGrantForm(page);

    // Should be in "specific" mode with Transfer selected
    const specificRadio = editDialog.locator('input[name="eventMode"][value="specific"]');
    await expect(specificRadio).toBeChecked();

    // Switch back to "All events visible"
    await editDialog.getByText('All events visible').click();

    const allRadio = editDialog.locator('input[name="eventMode"][value="all"]');
    await expect(allRadio).toBeChecked();

    // Save
    await editDialog.getByRole('button', { name: /save changes/i }).click();
    await expect(editDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API: event_rules should be null (all events)
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeNull();

    // Verify in the UI: permissions dialog should show "All events visible"
    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible();
    await expect(permDialog.getByText('All events visible')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group E: Contract without ABI — no event picker
// ---------------------------------------------------------------------------

test.describe('Event rules — contract without ABI', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('E1: no ABI shows warning when switching to specific events', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('ev-e1');
    await fixture.createGroup(org.id, 'grp-e1', { name: 'Group E1' });
    // Create contract WITHOUT ABI
    await fixture.createContract(org.id, { name: 'No ABI Contract' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events
    await grantDialog.getByText('Specific events only').click();

    // Should show "No ABI uploaded" warning instead of event picker
    await expect(grantDialog.getByText(/no abi uploaded/i)).toBeVisible({ timeout: 5000 });
  });
});
