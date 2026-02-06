import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Users', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('user is auto-created on authentication', async ({ request }) => {
    const { user, did } = await ctx.fixture.createUser(request);

    expect(user.id).toBeTruthy();
    expect(user.external_id).toBe(did);
    expect(user.banned).toBe(false);
  });

  test('updates user KYC status', async ({ request }) => {
    const { user } = await ctx.fixture.createUser(request, { kyc: false });

    expect(user.kyc).toBe(false);

    const updated = await ctx.rbac.updateUser(user.id, { kyc: true });

    expect(updated.kyc).toBe(true);
  });

  test('updates user banned status', async ({ request }) => {
    const { user } = await ctx.fixture.createUser(request);

    expect(user.banned).toBe(false);

    const updated = await ctx.rbac.updateUser(user.id, { banned: true });

    expect(updated.banned).toBe(true);
  });

  test('updates user note', async ({ request }) => {
    const { user } = await ctx.fixture.createUser(request);

    const updated = await ctx.rbac.updateUser(user.id, {
      note: 'Test note for user',
    });

    expect(updated.note).toBe('Test note for user');
  });

  test('updates user metadata', async ({ request }) => {
    const { user } = await ctx.fixture.createUser(request);

    const updated = await ctx.rbac.updateUser(user.id, {
      metadata: { department: 'engineering', level: 3 },
    });

    expect(updated.metadata).toEqual({ department: 'engineering', level: 3 });
  });

  test('lists users', async ({ request }) => {
    const { user } = await ctx.fixture.createUser(request);

    const users = await ctx.rbac.listUsers();

    expect(users.length).toBeGreaterThan(0);
    const found = users.find((u) => u.id === user.id);
    expect(found).toBeTruthy();
  });

  test('gets user by ID', async ({ request }) => {
    const { user } = await ctx.fixture.createUser(request);

    const retrieved = await ctx.rbac.getUser(user.id);

    expect(retrieved).not.toBeNull();
    expect(retrieved?.id).toBe(user.id);
    expect(retrieved?.external_id).toBe(user.external_id);
  });

  test('finds user by external ID', async ({ request }) => {
    const { user, did } = await ctx.fixture.createUser(request);

    const found = await ctx.rbac.findUserByExternalId(did);

    expect(found).not.toBeNull();
    expect(found?.id).toBe(user.id);
  });

  test('returns null for non-existent user', async () => {
    // Use a valid UUID format that doesn't exist
    const retrieved = await ctx.rbac.getUser('00000000-0000-0000-0000-000000000099');

    expect(retrieved).toBeNull();
  });

  test('adds membership to user', async ({ request }) => {
    const org = await ctx.fixture.createOrg('membershiporg');
    const group = await ctx.fixture.createGroup(org.id, 'membershipgroup');
    const { user } = await ctx.fixture.createUser(request);

    const membership = await ctx.rbac.createMembership(user.id, {
      group_id: group.id,
    });

    expect(membership.id).toBeTruthy();
    expect(membership.user_id).toBe(user.id);
    expect(membership.group_id).toBe(group.id);
    expect(membership.source).toBe('admin');
  });

  test('adds membership to group with access', async ({ request }) => {
    const org = await ctx.fixture.createOrg('memberroleorg');
    const group = await ctx.fixture.createGroup(org.id, 'memberrolegroup');
    const { user } = await ctx.fixture.createUser(request);

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write'],
    });

    const membership = await ctx.rbac.createMembership(user.id, {
      group_id: group.id,
    });

    expect(membership.group_id).toBe(group.id);
  });

  test('lists user memberships', async ({ request }) => {
    const org = await ctx.fixture.createOrg('listmemberorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'listgroup1');
    const group2 = await ctx.fixture.createGroup(org.id, 'listgroup2');
    const { user } = await ctx.fixture.createUser(request);

    await ctx.rbac.createMembership(user.id, { group_id: group1.id });
    await ctx.rbac.createMembership(user.id, { group_id: group2.id });

    const memberships = await ctx.rbac.listUserMemberships(user.id);

    // User has default membership + 2 new ones
    expect(memberships.length).toBeGreaterThanOrEqual(2);
    const groupIds = memberships.map((m) => m.membership.group_id);
    expect(groupIds).toContain(group1.id);
    expect(groupIds).toContain(group2.id);
  });

  test('removes membership from user', async ({ request }) => {
    const org = await ctx.fixture.createOrg('removeorg');
    const group = await ctx.fixture.createGroup(org.id, 'removegroup');
    const { user } = await ctx.fixture.createUser(request);

    const membership = await ctx.rbac.createMembership(user.id, {
      group_id: group.id,
    });

    // Verify membership exists
    let memberships = await ctx.rbac.listUserMemberships(user.id);
    expect(memberships.map((m) => m.membership.id)).toContain(membership.id);

    // Delete membership
    await ctx.rbac.deleteMembership(user.id, membership.id);

    // Verify it's gone
    memberships = await ctx.rbac.listUserMemberships(user.id);
    expect(memberships.map((m) => m.membership.id)).not.toContain(membership.id);
  });

  test('creates user with membership using fixture helper', async ({ request }) => {
    const org = await ctx.fixture.createOrg('fixtureorg');
    const group = await ctx.fixture.createGroup(org.id, 'fixturegroup');

    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read', 'write'],
    });

    const { user, membership } = await ctx.fixture.createUserWithMembership(request, group.id, {
      kyc: true,
    });

    expect(user.kyc).toBe(true);
    expect(membership.group_id).toBe(group.id);
  });

  test('adds multiple memberships using fixture helper', async ({ request }) => {
    const org = await ctx.fixture.createOrg('multimemberorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'multi1');
    const group2 = await ctx.fixture.createGroup(org.id, 'multi2');
    const { user } = await ctx.fixture.createUser(request);

    await ctx.fixture.addMembership(user.id, group1.id);
    await ctx.fixture.addMembership(user.id, group2.id);

    const memberships = await ctx.rbac.listUserMemberships(user.id);
    const groupIds = memberships.map((m) => m.membership.group_id);
    expect(groupIds).toContain(group1.id);
    expect(groupIds).toContain(group2.id);
  });
});
