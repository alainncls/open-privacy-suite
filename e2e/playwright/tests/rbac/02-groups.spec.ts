import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Groups', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('creates root group with depth 0', async () => {
    const org = await ctx.fixture.createOrg('grouporg');
    const group = await ctx.fixture.createGroup(org.id, 'rootgroup', {
      name: 'Root Group',
      description: 'A root level group',
    });

    expect(group.id).toBeTruthy();
    expect(group.org_id).toBe(org.id);
    expect(group.parent_id).toBeFalsy(); // null or undefined
    expect(group.slug).toContain('rootgroup_');
    expect(group.name).toBe('Root Group');
    expect(group.description).toBe('A root level group');
    expect(group.depth).toBe(0);
    expect(group.path).toBe(group.slug);
  });

  test('creates child group with depth 1', async () => {
    const org = await ctx.fixture.createOrg('childorg');
    const parent = await ctx.fixture.createGroup(org.id, 'parent');
    const child = await ctx.fixture.createGroup(org.id, 'child', {
      name: 'Child Group',
      parentId: parent.id,
    });

    expect(child.parent_id).toBe(parent.id);
    expect(child.depth).toBe(1);
    expect(child.path).toBe(`${parent.slug}.${child.slug}`);
  });

  test('creates 3-level hierarchy', async () => {
    const org = await ctx.fixture.createOrg('hierarchyorg');

    const level1 = await ctx.fixture.createGroup(org.id, 'l1');
    const level2 = await ctx.fixture.createGroup(org.id, 'l2', { parentId: level1.id });
    const level3 = await ctx.fixture.createGroup(org.id, 'l3', { parentId: level2.id });

    expect(level1.depth).toBe(0);
    expect(level2.depth).toBe(1);
    expect(level3.depth).toBe(2);

    expect(level1.path).toBe(level1.slug);
    expect(level2.path).toBe(`${level1.slug}.${level2.slug}`);
    expect(level3.path).toBe(`${level1.slug}.${level2.slug}.${level3.slug}`);
  });

  test('sets and retrieves group access', async () => {
    const org = await ctx.fixture.createOrg('permorg');
    const group = await ctx.fixture.createGroup(org.id, 'permgroup');

    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
      rate_limit_daily: 10000,
    });

    expect(access.group_id).toBe(group.id);
    expect(access.allowed_methods).toEqual(['eth_call', 'eth_getBalance']);
    expect(access.default_claims).toContain('read');
    expect(access.default_claims).toContain('write');
    expect(access.rate_limit_rps).toBe(100);
    expect(access.rate_limit_daily).toBe(10000);

    // Retrieve and verify
    const retrieved = await ctx.rbac.getGroupAccess(org.id, group.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.allowed_methods).toEqual(['eth_call', 'eth_getBalance']);
    expect(retrieved?.rate_limit_rps).toBe(100);
  });

  test('updates group access', async () => {
    const org = await ctx.fixture.createOrg('updatepermorg');
    const group = await ctx.fixture.createGroup(org.id, 'updatepermgroup');

    // Set initial access
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 50,
    });

    // Update access
    const updated = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
      default_claims: ['read', 'write'],
      rate_limit_rps: 100,
    });

    expect(updated.allowed_methods).toEqual(['eth_call', 'eth_getBalance', 'eth_blockNumber']);
    expect(updated.rate_limit_rps).toBe(100);
  });

  test('lists groups in organization', async () => {
    const org = await ctx.fixture.createOrg('listorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'listgroup1');
    const group2 = await ctx.fixture.createGroup(org.id, 'listgroup2');

    const groups = await ctx.rbac.listGroups(org.id);

    expect(groups.length).toBeGreaterThanOrEqual(2);
    const ids = groups.map((g) => g.id);
    expect(ids).toContain(group1.id);
    expect(ids).toContain(group2.id);
  });

  test('gets group by ID', async () => {
    const org = await ctx.fixture.createOrg('getorg');
    const group = await ctx.fixture.createGroup(org.id, 'getgroup', {
      name: 'Get Test Group',
    });

    const retrieved = await ctx.rbac.getGroup(org.id, group.id);

    expect(retrieved).not.toBeNull();
    expect(retrieved?.id).toBe(group.id);
    expect(retrieved?.name).toBe('Get Test Group');
  });

  test('returns null for non-existent group', async () => {
    const org = await ctx.fixture.createOrg('nogroup');

    // Use a valid UUID format that doesn't exist
    const retrieved = await ctx.rbac.getGroup(org.id, '00000000-0000-0000-0000-000000000099');

    expect(retrieved).toBeNull();
  });

  test('updates group name and description', async () => {
    const org = await ctx.fixture.createOrg('updateorg');
    const group = await ctx.fixture.createGroup(org.id, 'updategroup', {
      name: 'Original Name',
      description: 'Original description',
    });

    const updated = await ctx.rbac.updateGroup(org.id, group.id, {
      name: 'Updated Name',
      description: 'Updated description',
    });

    expect(updated.name).toBe('Updated Name');
    expect(updated.description).toBe('Updated description');
    expect(updated.slug).toBe(group.slug); // slug preserved
    expect(updated.path).toBe(group.path); // path preserved
  });

  test('deletes group', async () => {
    const org = await ctx.fixture.createOrg('deleteorg');
    const group = await ctx.fixture.createGroup(org.id, 'deletegroup');

    // Verify it exists
    let retrieved = await ctx.rbac.getGroup(org.id, group.id);
    expect(retrieved).not.toBeNull();

    // Delete it
    await ctx.rbac.deleteGroup(org.id, group.id);

    // Verify it's gone
    retrieved = await ctx.rbac.getGroup(org.id, group.id);
    expect(retrieved).toBeNull();
  });

  test('creates hierarchy using helper', async () => {
    const org = await ctx.fixture.createOrg('helperorg');

    const groups = await ctx.fixture.createGroupHierarchy(org.id, [
      {
        slug: 'root',
        name: 'Root',
        access: {
          allowed_methods: ['eth_call', 'eth_getBalance'],
          default_claims: ['read', 'write'],
          rate_limit_rps: 100,
        },
        children: [
          {
            slug: 'engineering',
            name: 'Engineering',
            access: {
              allowed_methods: ['eth_call'],
              default_claims: ['read', 'write'],
              rate_limit_rps: 50,
            },
            children: [
              {
                slug: 'devops',
                name: 'DevOps',
              },
            ],
          },
          {
            slug: 'marketing',
            name: 'Marketing',
          },
        ],
      },
    ]);

    expect(groups.size).toBe(4);
    expect(groups.get('root')).toBeTruthy();
    expect(groups.get('engineering')).toBeTruthy();
    expect(groups.get('devops')).toBeTruthy();
    expect(groups.get('marketing')).toBeTruthy();

    // Verify hierarchy
    const root = groups.get('root')!;
    const eng = groups.get('engineering')!;
    const devops = groups.get('devops')!;

    expect(root.depth).toBe(0);
    expect(eng.depth).toBe(1);
    expect(eng.parent_id).toBe(root.id);
    expect(devops.depth).toBe(2);
    expect(devops.parent_id).toBe(eng.id);

    // Verify access was set
    const rootAccess = await ctx.rbac.getGroupAccess(org.id, root.id);
    expect(rootAccess?.allowed_methods).toEqual(['eth_call', 'eth_getBalance']);
    expect(rootAccess?.rate_limit_rps).toBe(100);

    const engAccess = await ctx.rbac.getGroupAccess(org.id, eng.id);
    expect(engAccess?.allowed_methods).toEqual(['eth_call']);
    expect(engAccess?.rate_limit_rps).toBe(50);
  });
});
