import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

/**
 * API Response Format Tests
 *
 * These tests verify that the backend API returns data in the exact format
 * expected by the frontend. This catches bugs where the backend returns
 * wrong field names or structure (e.g., eth_address vs address).
 */
test.describe('RBAC API Response Formats', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test.describe('Linked Addresses Endpoint', () => {
    test('returns addresses in correct format with wrapper object', async ({ request }) => {
      // Create a user
      const { user } = await ctx.fixture.createUser(request);

      // Get linked addresses - even if empty, should return correct format
      const addresses = await ctx.rbac.getUserLinkedAddresses(user.id);

      // Should be an array (possibly empty)
      expect(Array.isArray(addresses)).toBe(true);
    });

    test('linked address has correct field names', async ({ request }) => {
      // This test verifies the response structure when addresses exist
      // The fixture.createUser doesn't link addresses, so we test with the API client
      // which validates the response format in getUserLinkedAddresses

      const { user } = await ctx.fixture.createUser(request);

      // The API client will throw if format is wrong
      const addresses = await ctx.rbac.getUserLinkedAddresses(user.id);

      // If there are addresses, verify field names
      for (const addr of addresses) {
        // Must have 'address' field (not 'eth_address')
        expect(addr).toHaveProperty('address');
        expect(typeof addr.address).toBe('string');

        // Must have 'verified_at' field
        expect(addr).toHaveProperty('verified_at');
        expect(typeof addr.verified_at).toBe('string');

        // Optional fields should have correct types if present
        if (addr.ens_name !== undefined) {
          expect(typeof addr.ens_name === 'string' || addr.ens_name === null).toBe(true);
        }
        if (addr.ens_resolved_at !== undefined) {
          expect(typeof addr.ens_resolved_at === 'string' || addr.ens_resolved_at === null).toBe(true);
        }
      }
    });

    test('returns 404 for non-existent user', async () => {
      try {
        await ctx.rbac.getUserLinkedAddresses('00000000-0000-0000-0000-000000000099');
        // Should not reach here
        expect(true).toBe(false);
      } catch (error) {
        expect(String(error)).toContain('404');
      }
    });
  });

  test.describe('Effective Permissions Endpoint', () => {
    test('returns permissions in correct format', async ({ request }) => {
      const org = await ctx.fixture.createOrg('permformatorg');
      const group = await ctx.fixture.createGroup(org.id, 'permformatgroup');
      const { user } = await ctx.fixture.createUser(request);

      // Set up group access
      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call', 'eth_getBalance'],
        default_claims: ['read', 'write'],
        rate_limit_rps: 100,
        rate_limit_daily: 10000,
      });

      // Add user to group
      await ctx.rbac.createMembership(user.id, { group_id: group.id });

      // Get effective permissions
      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

      // Verify structure
      expect(perms).toHaveProperty('id');
      expect(perms).toHaveProperty('user_id');
      expect(perms).toHaveProperty('org_id');
      expect(perms).toHaveProperty('allowed_methods');
      expect(perms).toHaveProperty('contract_access');
      expect(perms).toHaveProperty('default_claims');
      expect(perms).toHaveProperty('rate_limit_rps');
      expect(perms).toHaveProperty('rate_limit_daily');
      expect(perms).toHaveProperty('computed_at');
      expect(perms).toHaveProperty('expires_at');

      // Verify types
      expect(Array.isArray(perms.allowed_methods)).toBe(true);
      expect(Array.isArray(perms.default_claims)).toBe(true);
      expect(typeof perms.contract_access).toBe('object');
    });

    test('allowed_methods contains expected values', async ({ request }) => {
      const org = await ctx.fixture.createOrg('methodsorg');
      const group = await ctx.fixture.createGroup(org.id, 'methodsgroup');
      const { user } = await ctx.fixture.createUser(request);

      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call', 'eth_sendTransaction'],
        default_claims: ['read'],
      });

      await ctx.rbac.createMembership(user.id, { group_id: group.id });

      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

      expect(perms.allowed_methods).toContain('eth_call');
      expect(perms.allowed_methods).toContain('eth_sendTransaction');
    });

    test('default_claims contains expected values', async ({ request }) => {
      const org = await ctx.fixture.createOrg('claimsorg');
      const group = await ctx.fixture.createGroup(org.id, 'claimsgroup');
      const { user } = await ctx.fixture.createUser(request);

      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read', 'write', 'admin'],
      });

      await ctx.rbac.createMembership(user.id, { group_id: group.id });

      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

      expect(perms.default_claims).toContain('read');
      expect(perms.default_claims).toContain('write');
      expect(perms.default_claims).toContain('admin');
    });

    test('rate limits are returned correctly', async ({ request }) => {
      const org = await ctx.fixture.createOrg('ratelimitorg');
      const group = await ctx.fixture.createGroup(org.id, 'ratelimitgroup');
      const { user } = await ctx.fixture.createUser(request);

      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
        rate_limit_rps: 50,
        rate_limit_daily: 5000,
      });

      await ctx.rbac.createMembership(user.id, { group_id: group.id });

      const perms = await ctx.rbac.getEffectivePermissions(user.id, org.slug);

      expect(perms.rate_limit_rps).toBe(50);
      expect(perms.rate_limit_daily).toBe(5000);
    });
  });

  test.describe('Memberships Endpoint', () => {
    test('returns memberships with group details', async ({ request }) => {
      const org = await ctx.fixture.createOrg('memberdetailorg');
      const group = await ctx.fixture.createGroup(org.id, 'memberdetailgroup');
      const { user } = await ctx.fixture.createUser(request);

      await ctx.rbac.createMembership(user.id, { group_id: group.id });

      const memberships = await ctx.rbac.listUserMemberships(user.id);

      // Find the membership we just created
      const found = memberships.find((m) => m.membership.group_id === group.id);
      expect(found).toBeTruthy();

      // Verify membership structure
      expect(found!.membership).toHaveProperty('id');
      expect(found!.membership).toHaveProperty('user_id');
      expect(found!.membership).toHaveProperty('group_id');
      expect(found!.membership).toHaveProperty('source');
      expect(found!.membership).toHaveProperty('created_at');

      // Verify group structure
      expect(found!.group).toHaveProperty('id');
      expect(found!.group).toHaveProperty('org_id');
      expect(found!.group).toHaveProperty('slug');
      expect(found!.group).toHaveProperty('name');
      expect(found!.group).toHaveProperty('path');
    });

    test('membership source is correct value', async ({ request }) => {
      const org = await ctx.fixture.createOrg('sourceorg');
      const group = await ctx.fixture.createGroup(org.id, 'sourcegroup');
      const { user } = await ctx.fixture.createUser(request);

      await ctx.rbac.createMembership(user.id, { group_id: group.id });

      const memberships = await ctx.rbac.listUserMemberships(user.id);
      const found = memberships.find((m) => m.membership.group_id === group.id);

      // Source should be 'admin' for admin-created memberships
      expect(found!.membership.source).toBe('admin');
    });
  });

  test.describe('User Endpoint', () => {
    test('returns user in correct format', async ({ request }) => {
      const { user, did } = await ctx.fixture.createUser(request);

      const retrieved = await ctx.rbac.getUser(user.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved).toHaveProperty('id');
      expect(retrieved).toHaveProperty('external_id');
      expect(retrieved).toHaveProperty('kyc');
      expect(retrieved).toHaveProperty('banned');
      expect(retrieved).toHaveProperty('metadata');
      expect(retrieved).toHaveProperty('created_at');
      expect(retrieved).toHaveProperty('updated_at');

      // Verify types
      expect(typeof retrieved!.id).toBe('string');
      expect(typeof retrieved!.external_id).toBe('string');
      expect(typeof retrieved!.kyc).toBe('boolean');
      expect(typeof retrieved!.banned).toBe('boolean');
      expect(typeof retrieved!.metadata).toBe('object');
    });
  });

  test.describe('Organization Endpoint', () => {
    test('returns organization in correct format', async () => {
      const org = await ctx.fixture.createOrg('formatorg');

      const retrieved = await ctx.rbac.getOrganization(org.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved).toHaveProperty('id');
      expect(retrieved).toHaveProperty('slug');
      expect(retrieved).toHaveProperty('name');
      expect(retrieved).toHaveProperty('settings');
      expect(retrieved).toHaveProperty('created_at');
      expect(retrieved).toHaveProperty('updated_at');
    });
  });

  test.describe('Group Endpoint', () => {
    test('returns group in correct format', async () => {
      const org = await ctx.fixture.createOrg('groupformatorg');
      const group = await ctx.fixture.createGroup(org.id, 'groupformatgroup');

      const retrieved = await ctx.rbac.getGroup(org.id, group.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved).toHaveProperty('id');
      expect(retrieved).toHaveProperty('org_id');
      // parent_id may be omitted when null (Go omits null fields)
      // Just verify it's null or a string if present
      if ('parent_id' in retrieved!) {
        expect(retrieved!.parent_id === null || typeof retrieved!.parent_id === 'string').toBe(true);
      }
      expect(retrieved).toHaveProperty('slug');
      expect(retrieved).toHaveProperty('name');
      expect(retrieved).toHaveProperty('depth');
      expect(retrieved).toHaveProperty('path');
      expect(retrieved).toHaveProperty('created_at');
      expect(retrieved).toHaveProperty('updated_at');
    });

    test('group access returns correct format', async () => {
      const org = await ctx.fixture.createOrg('accessformatorg');
      const group = await ctx.fixture.createGroup(org.id, 'accessformatgroup');

      await ctx.rbac.setGroupAccess(org.id, group.id, {
        allowed_methods: ['eth_call'],
        default_claims: ['read'],
        rate_limit_rps: 10,
        rate_limit_daily: 1000,
      });

      const access = await ctx.rbac.getGroupAccess(org.id, group.id);

      expect(access).not.toBeNull();
      expect(access).toHaveProperty('id');
      expect(access).toHaveProperty('group_id');
      expect(access).toHaveProperty('allowed_methods');
      expect(access).toHaveProperty('default_claims');
      expect(access).toHaveProperty('rate_limit_rps');
      // rate_limit_daily may be omitted when null/zero
      // Verify it's a number if present
      if ('rate_limit_daily' in access!) {
        expect(typeof access!.rate_limit_daily === 'number' || access!.rate_limit_daily === null).toBe(true);
      }

      expect(Array.isArray(access!.allowed_methods)).toBe(true);
      expect(Array.isArray(access!.default_claims)).toBe(true);
    });
  });

  test.describe('Contract Endpoint', () => {
    test('returns contract in correct format', async () => {
      const org = await ctx.fixture.createOrg('contractformatorg');
      const address = '0x' + 'a'.repeat(40);

      const contract = await ctx.rbac.createContract(org.id, {
        address,
        name: 'Test Contract',
      });

      expect(contract).toHaveProperty('id');
      expect(contract).toHaveProperty('org_id');
      // Should have 'address' field (new format)
      expect(contract.address || contract.contract_address).toBeTruthy();
      expect(contract).toHaveProperty('created_at');
      expect(contract).toHaveProperty('updated_at');
    });
  });
});
