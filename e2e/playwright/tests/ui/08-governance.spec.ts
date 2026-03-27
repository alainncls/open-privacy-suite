import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

// Generate unique names/slugs for test organizations to avoid collisions
const uniqueSuffix = () => `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
const generateOrgName = () => `Gov Test Org ${uniqueSuffix()}`;
const generateOrgSlug = () => `gov-test-org-${uniqueSuffix()}`;

const ADMIN_URL = process.env.ADMIN_URL || 'http://proxy-backend:8080';
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token';

test.describe('Governance Dashboard Lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    // Hide massive DOM dumps during regular runs, focus on actual functional errors
    page.on('pageerror', err => console.log('BROWSER ERROR:', err.message));
    await mockLoginViaAPI(page);
  });

  test('can enable governance, submit intercepted actions, and approve/reject them', async ({ page, request }) => {
    // Increase timeout for this comprehensive test
    test.setTimeout(45000);
    
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    // 1. Create an org to test Governance
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });
    
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    // 2. Select the org and navigate to Governance tab
    await orgRow.click();
    await page.getByTestId('tab-governance').click();

    // 3. Enable Governance Settings
    const enableCheckbox = page.getByRole('checkbox', { name: /Enable Governance Approvals/i });
    await expect(enableCheckbox).toBeVisible();
    await enableCheckbox.check();

    const thresholdInput = page.getByLabel(/Approval Threshold/i);
    await expect(thresholdInput).toBeVisible({ timeout: 5000 });
    await thresholdInput.fill('1');

    await page.getByRole('button', { name: /Save Settings/i }).click();

    // Verify it saved successfully (no error toast)
    await expect(page.locator('.bg-error-light')).not.toBeVisible();

    // 4. Fetch the created Org ID via the Admin API
    const orgsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs?limit=100`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN }
    });
    const orgs = await orgsRes.json();
    const org = orgs.data.find((o: any) => o.slug === orgSlug);
    expect(org).toBeDefined();

    // 5. Create a test Group via API to mutate later
    const groupRes = await request.post(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN, 'Content-Type': 'application/json' },
      data: { slug: 'test-mutating-group', name: 'Mutating Group' }
    });
    expect(groupRes.ok()).toBeTruthy();
    
    const groupsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN }
    });
    const groups = await groupsRes.json();
    const group = groups.data.find((g: any) => g.group.slug === 'test-mutating-group');
    expect(group).toBeDefined();

    // MINT TEST USER 2 TOKEN to act as the Requester (avoids DB constraint 500 error from 'system' requester_id)
    const user2ReqRes = await request.post(`${ADMIN_URL}/auth/request`, { headers: { 'Content-Type': 'application/json' } });
    const u2Session = await user2ReqRes.json();
    const user2VerifyRes = await request.post(`${ADMIN_URL}/auth/verify`, {
      headers: { 'Content-Type': 'application/json' },
      data: { session_id: u2Session.session_id, jwz_token: 'mock.did:privado:dev_user2' }
    });
    const user2Data = await user2VerifyRes.json();
    const user2Token = user2Data.access_token;

    // Add User 2 to the Global Admin Group to bypass standard auth restrictions
    const adminGroupsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs/${orgs.data.find((o: any) => o.slug === 'e2e-admin-org').id}/groups`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN }
    });
    const e2eAdminGroups = await adminGroupsRes.json();
    const adminGroupId = e2eAdminGroups.data.find((g: any) => g.group.slug === 'e2e-admin-group').group.id;
    
    const userRes = await request.get(`${ADMIN_URL}/api/v1/admin/users?limit=1000`, { headers: { 'X-Admin-Token': ADMIN_TOKEN }});
    const allUsers = await userRes.json();
    const user2Id = allUsers.data.find((u: any) => u.external_id === 'did:privado:dev_user2').id;

    await request.post(`${ADMIN_URL}/api/v1/admin/users/${user2Id}/memberships`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN, 'Content-Type': 'application/json' },
      data: { group_id: adminGroupId }
    });

    // 6. Simulate User 2 attempting to modify Group Access (Intercepted Action)
    const interceptedRes1 = await request.put(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups/${group.group.id}/access`, {
      headers: { 'Authorization': `Bearer ${user2Token}`, 'Content-Type': 'application/json' },
      data: { allowed_methods: ['eth_call'], claims: ['some_claim'] }
    });
    
    // The middleware should return 202 Accepted because Governance is enabled!
    expect(interceptedRes1.status()).toBe(202);

    // 7. Verify the Pending Request in the BROWSER UI (Logged in as User 1)
    await page.getByTestId('tab-contracts').click();
    await page.getByTestId('tab-governance').click();

    // Wait for the request row to load
    await expect(page.getByText('updateGroupAccess')).toBeVisible({ timeout: 10000 });

    // 8. Approve the Request!
    const approveBtn = page.getByRole('button', { name: 'Approve' }).first();
    await approveBtn.click();

    // The list should now be empty of pending requests
    await expect(page.getByText('No pending requests at this time.')).toBeVisible({ timeout: 10000 });

    // 9. Simulate a SECOND intercepted action via User 2 to test Rejection
    const interceptedRes2 = await request.put(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups/${group.group.id}/access`, {
      headers: { 'Authorization': `Bearer ${user2Token}`, 'Content-Type': 'application/json' },
      data: { allowed_methods: ['eth_sendTransaction'], claims: ['admin'] }
    });
    expect(interceptedRes2.status()).toBe(202);

    // Refresh UI
    await page.getByTestId('tab-contracts').click();
    await page.getByTestId('tab-governance').click();

    await expect(page.getByText('updateGroupAccess')).toBeVisible({ timeout: 10000 });

    // 10. Reject the Request!
    const rejectBtn = page.getByRole('button', { name: 'Reject' }).first();
    await rejectBtn.click();

    // The list should clear rapidly
    await expect(page.getByText('No pending requests at this time.')).toBeVisible({ timeout: 10000 });
  });

  test('can handle multi-sig approvals with threshold > 1', async ({ page, request }) => {
    test.setTimeout(45000);
    const orgName = generateOrgName();
    const orgSlug = generateOrgSlug();

    // 1. Setup Org and Set Threshold = 2
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });
    
    await page.getByRole('button', { name: /add organization/i }).click();
    const dialog = page.locator(selectors.common.dialog);
    await dialog.getByLabel(/name/i).fill(orgName);
    await dialog.getByLabel(/slug/i).fill(orgSlug);
    await dialog.getByRole('button', { name: /create organization/i }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });
    await orgRow.click();
    await page.getByTestId('tab-governance').click();

    // Set Governance = True, Threshold = 2
    const enableCheckbox = page.getByRole('checkbox', { name: /Enable Governance Approvals/i });
    await expect(enableCheckbox).toBeVisible();
    await enableCheckbox.check();

    const thresholdInput = page.getByLabel(/Approval Threshold/i);
    await expect(thresholdInput).toBeVisible({ timeout: 5000 });
    await thresholdInput.fill('2'); // Multi-sig!
    
    await page.getByRole('button', { name: /Save Settings/i }).click();
    await expect(page.locator('.bg-error-light')).not.toBeVisible();

    // Fetch Org ID and Group
    const orgsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs?limit=100`, { headers: { 'X-Admin-Token': ADMIN_TOKEN } });
    const orgs = await orgsRes.json();
    const org = orgs.data.find((o: any) => o.slug === orgSlug);

    const groupRes = await request.post(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN, 'Content-Type': 'application/json' },
      data: { slug: 'test-multisig-group', name: 'MultiSig Group' }
    });
    
    const groupsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups`, { headers: { 'X-Admin-Token': ADMIN_TOKEN } });
    const groups = await groupsRes.json();
    const group = groups.data.find((g: any) => g.group.slug === 'test-multisig-group');

    // 2. Submit change as Requester (`system` token)
    await request.put(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups/${group.group.id}/access`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN, 'Content-Type': 'application/json' },
      data: { allowed_methods: ['eth_getBalance'], claims: ['multisig_claim'] }
    });

    // 3. Navigate Browser to see the pending request
    await page.getByTestId('tab-contracts').click();
    await page.getByTestId('tab-governance').click();

    // The UI should display the pending request
    await expect(page.getByText('updateGroupAccess')).toBeVisible({ timeout: 10000 });

    // 4. User 1 (Browser) Approves
    const approveBtn = page.getByRole('button', { name: 'Approve' }).first();
    await approveBtn.click();

    // Verify request does NOT disappear yet because threshold is 2!
    // We wait 3 seconds to ensure it doesn't clear aggressively.
    await page.waitForTimeout(3000);
    await expect(page.getByText('updateGroupAccess')).toBeVisible();
    await expect(page.getByText('updateGroupAccess')).toBeVisible();

    // 5. User 2 (API) Approves to complete the multisig execution
    // We must find the request ID first
    const reqsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/governance/requests`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN } // System token cannot be used because it was the Requester!
    });
    const reqs = await reqsRes.json();
    const pendingReq = reqs.data.find((r: any) => r.status === 'pending');

    // To simulate a third unique identity, we fetch an actual JWT for a mocked user DID
    const user3ReqRes = await request.post(`${ADMIN_URL}/auth/request`, { headers: { 'Content-Type': 'application/json' } });
    const { session_id } = await user3ReqRes.json();
    const user3VerifyRes = await request.post(`${ADMIN_URL}/auth/verify`, {
      headers: { 'Content-Type': 'application/json' },
      data: { session_id, jwz_token: 'mock.did:privado:dev_user3' }
    });
    const user3Data = await user3VerifyRes.json();
    const user3Token = user3Data.access_token;
    
    // Add user 3 to the Admin Group directly via DB/API bypassing governance to ensure they have the Claim
    const adminGroupsRes = await request.get(`${ADMIN_URL}/api/v1/admin/orgs/${orgs.data.find((o: any) => o.slug === 'e2e-admin-org').id}/groups`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN }
    });
    const e2eAdminGroups = await adminGroupsRes.json();
    const adminGroupId = e2eAdminGroups.data.find((g: any) => g.group.slug === 'e2e-admin-group').group.id;
    
    const userRes = await request.get(`${ADMIN_URL}/api/v1/admin/users?limit=1000`, { headers: { 'X-Admin-Token': ADMIN_TOKEN }});
    const allUsers = await userRes.json();
    const user3Id = allUsers.data.find((u: any) => u.external_id === 'did:privado:dev_user3').id;

    await request.post(`${ADMIN_URL}/api/v1/admin/users/${user3Id}/memberships`, {
      headers: { 'X-Admin-Token': ADMIN_TOKEN, 'Content-Type': 'application/json' },
      data: { group_id: adminGroupId }
    });

    // User 3 approves the request
    await request.post(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/governance/requests/${pendingReq.id}/approve`, {
      headers: { 'Authorization': `Bearer ${user3Token}` }
    });

    // 6. Verify Execution Complete in the Browser UI
    await page.getByTestId('tab-contracts').click();
    await page.getByTestId('tab-governance').click();

    await expect(page.getByText('No pending requests at this time.')).toBeVisible({ timeout: 10000 });
  });
});

