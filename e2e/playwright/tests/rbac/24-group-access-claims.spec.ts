import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Group Access - Claim-Method Validation', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('rejects write methods without write claim', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org1');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group1');

    // Try to set write methods without write claim
    let errorMessage = '';
    try {
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call', 'eth_sendTransaction'],
        claims: ['read'], // Missing 'write'!
      });
    } catch (err) {
      errorMessage = (err as Error).message;
    }

    expect(errorMessage).toContain('eth_sendTransaction');
    expect(errorMessage).toContain('write claim');
  });

  test('rejects read methods without read claim', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org2');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group2');

    // Try to set read methods without read claim
    let errorMessage = '';
    try {
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call', 'eth_getBalance'],
        claims: ['write'], // Missing 'read'!
      });
    } catch (err) {
      errorMessage = (err as Error).message;
    }

    expect(errorMessage).toContain('read claim');
  });

  test('accepts matching methods and claims', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org3');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group3');

    // Set matching methods and claims - should succeed
    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_getBalance', 'eth_sendTransaction'],
      claims: ['read', 'write'],
    });

    expect(access.allowed_methods).toContain('eth_call');
    expect(access.allowed_methods).toContain('eth_sendTransaction');
    expect(access.claims).toContain('read');
    expect(access.claims).toContain('write');
  });

  test('accepts empty methods list with no claims', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org4');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group4');

    // Empty methods list with empty claims - should succeed
    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: [],
      claims: [],
    });

    expect(access.allowed_methods).toEqual([]);
    expect(access.claims).toEqual([]);
  });

  test('accepts unknown methods without claims', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org5');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group5');

    // Unknown methods don't require specific claims
    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['some_unknown_method', 'custom_method'],
      claims: [],
    });

    expect(access.allowed_methods).toContain('some_unknown_method');
    expect(access.allowed_methods).toContain('custom_method');
  });

  test('accepts all claims with any known methods', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org6');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group6');

    // All claims provided - all methods should work
    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: [
        'eth_chainId',
        'eth_call',
        'eth_getBalance',
        'eth_sendTransaction',
        'eth_sendRawTransaction',
      ],
      claims: ['read', 'write', 'admin', 'upgrade', 'deploy'],
    });

    expect(access.allowed_methods.length).toBe(5);
    expect(access.claims.length).toBe(5);
  });

  test('rejects mixed read/write methods with only read claim', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org7');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group7');

    // Mix of read and write methods with only read claim
    let errorMessage = '';
    try {
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call', 'eth_chainId', 'eth_sendRawTransaction'],
        claims: ['read'], // Missing 'write'!
      });
    } catch (err) {
      errorMessage = (err as Error).message;
    }

    expect(errorMessage).toContain('eth_sendRawTransaction');
    expect(errorMessage).toContain('write claim');
  });

  test('admin claim expands to all claims', async () => {
    const org = await ctx.fixture.createOrg('claim-expand-admin');
    const group = await ctx.fixture.createGroup(org.id, 'claim-expand-admin-g');

    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['admin'],
    });

    // admin should expand to include all claims
    expect(access.claims).toContain('admin');
    expect(access.claims).toContain('read');
    expect(access.claims).toContain('write');
    expect(access.claims).toContain('deploy');
    expect(access.claims).toContain('upgrade');
    expect(access.claims.length).toBe(5);
  });

  test('deploy claim expands to include read and write', async () => {
    const org = await ctx.fixture.createOrg('claim-expand-deploy');
    const group = await ctx.fixture.createGroup(org.id, 'claim-expand-deploy-g');

    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['deploy'],
    });

    expect(access.claims).toContain('deploy');
    expect(access.claims).toContain('read');
    expect(access.claims).toContain('write');
    expect(access.claims.length).toBe(3);
  });

  test('upgrade claim expands to include read and write', async () => {
    const org = await ctx.fixture.createOrg('claim-expand-upgrade');
    const group = await ctx.fixture.createGroup(org.id, 'claim-expand-upgrade-g');

    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['upgrade'],
    });

    expect(access.claims).toContain('upgrade');
    expect(access.claims).toContain('read');
    expect(access.claims).toContain('write');
    expect(access.claims.length).toBe(3);
  });

  test('deploy + upgrade expands to include read and write (deduplicated)', async () => {
    const org = await ctx.fixture.createOrg('claim-expand-both');
    const group = await ctx.fixture.createGroup(org.id, 'claim-expand-both-g');

    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['deploy', 'upgrade'],
    });

    expect(access.claims).toContain('deploy');
    expect(access.claims).toContain('upgrade');
    expect(access.claims).toContain('read');
    expect(access.claims).toContain('write');
    expect(access.claims.length).toBe(4);
  });

  test('deploy claim allows write methods via expansion', async () => {
    const org = await ctx.fixture.createOrg('claim-expand-methods');
    const group = await ctx.fixture.createGroup(org.id, 'claim-expand-methods-g');

    // deploy implies write, so eth_sendTransaction should be allowed
    const access = await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call', 'eth_sendTransaction'],
      claims: ['deploy'],
    });

    expect(access.allowed_methods).toContain('eth_sendTransaction');
    expect(access.claims).toContain('write');
  });

  test('validation works when updating existing access', async () => {
    const org = await ctx.fixture.createOrg('claim-val-org8');
    const group = await ctx.fixture.createGroup(org.id, 'claim-val-group8');

    // First, set valid access
    await ctx.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['eth_call'],
      claims: ['read'],
    });

    // Try to update with invalid combination
    let errorMessage = '';
    try {
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call', 'eth_sendTransaction'],
        claims: ['read'], // Still missing 'write'!
      });
    } catch (err) {
      errorMessage = (err as Error).message;
    }

    expect(errorMessage).toContain('eth_sendTransaction');
    expect(errorMessage).toContain('write claim');

    // Verify original access is preserved
    const currentAccess = await ctx.rbac.getGroupAccess(org.id, group.id);
    expect(currentAccess?.allowed_methods).toEqual(['eth_call']);
  });
});
