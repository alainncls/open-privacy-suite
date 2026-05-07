import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Organizations', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('creates organization with unique slug', async () => {
    const org = await ctx.fixture.createOrg('myorg', 'My Test Organization');

    expect(org.id).toBeTruthy();
    expect(org.slug).toContain('myorg-');
    expect(org.slug).toContain(ctx.testId);
    expect(org.name).toBe('My Test Organization');
    expect(org.settings).toEqual({});
    expect(org.created_at).toBeTruthy();
    expect(org.updated_at).toBeTruthy();
  });

  test('list orgs includes created organization', async () => {
    const org = await ctx.fixture.createOrg('listtest');

    const orgs = await ctx.rbac.listOrganizations();

    expect(orgs.length).toBeGreaterThan(0);
    const found = orgs.find((o) => o.id === org.id);
    expect(found).toBeTruthy();
    expect(found?.slug).toBe(org.slug);
  });

  test('gets organization by ID', async () => {
    const created = await ctx.fixture.createOrg('gettest', 'Get Test Org');

    const retrieved = await ctx.rbac.getOrganization(created.id);

    expect(retrieved).not.toBeNull();
    expect(retrieved?.id).toBe(created.id);
    expect(retrieved?.slug).toBe(created.slug);
    expect(retrieved?.name).toBe('Get Test Org');
  });

  test('returns null for non-existent organization', async () => {
    // Use a valid UUID format that doesn't exist
    const retrieved = await ctx.rbac.getOrganization('00000000-0000-0000-0000-000000000099');

    expect(retrieved).toBeNull();
  });

  test('updates organization name', async () => {
    const org = await ctx.fixture.createOrg('updatetest', 'Original Name');

    const updated = await ctx.rbac.updateOrganization(org.id, {
      name: 'Updated Name',
    });

    expect(updated.id).toBe(org.id);
    expect(updated.slug).toBe(org.slug); // slug preserved
    expect(updated.name).toBe('Updated Name');
  });

  test('updates organization settings', async () => {
    const org = await ctx.fixture.createOrg('settingstest');

    const updated = await ctx.rbac.updateOrganization(org.id, {
      settings: { custom_setting: 'value', count: 42 },
    });

    expect(updated.settings).toEqual({ custom_setting: 'value', count: 42 });
  });

  test('rejects duplicate slug on create', async () => {
    const org1 = await ctx.fixture.createOrg('duptest');

    // Try to create another org with the exact same slug
    await expect(
      ctx.rbac.createOrganization({
        slug: org1.slug, // Use exact same slug
        name: 'Duplicate Org',
      })
    ).rejects.toThrow();
  });

  test('creates multiple organizations independently', async () => {
    const org1 = await ctx.fixture.createOrg('multi1', 'First Org');
    const org2 = await ctx.fixture.createOrg('multi2', 'Second Org');

    expect(org1.id).not.toBe(org2.id);
    expect(org1.slug).not.toBe(org2.slug);

    // Both should be retrievable
    const retrieved1 = await ctx.rbac.getOrganization(org1.id);
    const retrieved2 = await ctx.rbac.getOrganization(org2.id);

    expect(retrieved1?.name).toBe('First Org');
    expect(retrieved2?.name).toBe('Second Org');
  });
});
