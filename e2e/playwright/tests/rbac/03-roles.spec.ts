import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';
import { Claim } from '../../helpers/rbac-api.js';

test.describe('RBAC Roles', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('creates role with claims', async () => {
    const org = await ctx.fixture.createOrg('roleorg');
    const role = await ctx.fixture.createRole(org.id, 'testrole', ['reader', 'writer']);

    expect(role.id).toBeTruthy();
    expect(role.org_id).toBe(org.id);
    expect(role.name).toContain('testrole_');
    expect(role.claims).toEqual(['reader', 'writer']);
  });

  test('creates admin role with all claims', async () => {
    const org = await ctx.fixture.createOrg('adminroleorg');
    const role = await ctx.fixture.createAdminRole(org.id);

    const allClaims: Claim[] = ['reader', 'writer', 'deployer', 'admin', 'upgrade'];
    expect(role.claims).toEqual(allClaims);
  });

  test('creates reader role', async () => {
    const org = await ctx.fixture.createOrg('readerorg');
    const role = await ctx.fixture.createReaderRole(org.id);

    expect(role.claims).toEqual(['reader']);
  });

  test('creates writer role', async () => {
    const org = await ctx.fixture.createOrg('writerorg');
    const role = await ctx.fixture.createWriterRole(org.id);

    expect(role.claims).toEqual(['reader', 'writer']);
  });

  test('creates role with empty claims', async () => {
    const org = await ctx.fixture.createOrg('emptyorg');
    const role = await ctx.fixture.createRole(org.id, 'empty');

    expect(role.claims).toEqual([]);
  });

  test('updates role claims', async () => {
    const org = await ctx.fixture.createOrg('updateclaimsorg');
    const role = await ctx.fixture.createRole(org.id, 'updatable', ['reader']);

    const updated = await ctx.rbac.updateRole(org.id, role.id, {
      claims: ['reader', 'writer', 'deployer'],
    });

    expect(updated.claims).toEqual(['reader', 'writer', 'deployer']);
  });

  test('updates role name and description', async () => {
    const org = await ctx.fixture.createOrg('updatenameorg');
    const role = await ctx.fixture.createRole(org.id, 'original', ['reader']);

    const updated = await ctx.rbac.updateRole(org.id, role.id, {
      name: 'Updated Role Name',
      description: 'Updated description',
    });

    expect(updated.name).toBe('Updated Role Name');
    expect(updated.description).toBe('Updated description');
    expect(updated.claims).toEqual(['reader']); // Claims unchanged
  });

  test('removes claims from role', async () => {
    const org = await ctx.fixture.createOrg('removeclaimsorg');
    const role = await ctx.fixture.createRole(org.id, 'manyclaims', [
      'reader',
      'writer',
      'deployer',
    ]);

    const updated = await ctx.rbac.updateRole(org.id, role.id, {
      claims: ['reader'],
    });

    expect(updated.claims).toEqual(['reader']);
  });

  test('lists roles in organization', async () => {
    const org = await ctx.fixture.createOrg('listorg');
    const role1 = await ctx.fixture.createRole(org.id, 'role1', ['reader']);
    const role2 = await ctx.fixture.createRole(org.id, 'role2', ['writer']);

    const roles = await ctx.rbac.listRoles(org.id);

    expect(roles.length).toBeGreaterThanOrEqual(2);
    const ids = roles.map((r) => r.id);
    expect(ids).toContain(role1.id);
    expect(ids).toContain(role2.id);
  });

  test('gets role by ID', async () => {
    const org = await ctx.fixture.createOrg('getorg');
    const role = await ctx.fixture.createRole(org.id, 'getrole', ['admin']);

    const retrieved = await ctx.rbac.getRole(org.id, role.id);

    expect(retrieved).not.toBeNull();
    expect(retrieved?.id).toBe(role.id);
    expect(retrieved?.claims).toEqual(['admin']);
  });

  test('returns null for non-existent role', async () => {
    const org = await ctx.fixture.createOrg('norole');

    // Use a valid UUID format that doesn't exist
    const retrieved = await ctx.rbac.getRole(org.id, '00000000-0000-0000-0000-000000000099');

    expect(retrieved).toBeNull();
  });

  test('deletes role', async () => {
    const org = await ctx.fixture.createOrg('deleteorg');
    const role = await ctx.fixture.createRole(org.id, 'todelete', ['reader']);

    // Verify it exists
    let retrieved = await ctx.rbac.getRole(org.id, role.id);
    expect(retrieved).not.toBeNull();

    // Delete it
    await ctx.rbac.deleteRole(org.id, role.id);

    // Verify it's gone
    retrieved = await ctx.rbac.getRole(org.id, role.id);
    expect(retrieved).toBeNull();
  });

  test('creates multiple roles with different claims', async () => {
    const org = await ctx.fixture.createOrg('multiorg');

    const viewer = await ctx.fixture.createRole(org.id, 'viewer', ['reader']);
    const editor = await ctx.fixture.createRole(org.id, 'editor', ['reader', 'writer']);
    const admin = await ctx.fixture.createRole(org.id, 'admin', [
      'reader',
      'writer',
      'deployer',
      'admin',
      'upgrade',
    ]);

    expect(viewer.claims.length).toBe(1);
    expect(editor.claims.length).toBe(2);
    expect(admin.claims.length).toBe(5);
  });
});
