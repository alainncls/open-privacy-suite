import { test, expect } from '@playwright/test';
import { RBACTestContext } from '../../helpers/test-context.js';

test.describe('RBAC Contracts', () => {
  let ctx: RBACTestContext;

  test.beforeEach(async ({ request }) => {
    ctx = new RBACTestContext(request);
  });

  test.afterEach(async () => {
    await ctx.cleanup();
  });

  test('creates contract', async () => {
    const org = await ctx.fixture.createOrg('contractorg');
    const address = ctx.contractAddress();

    const contract = await ctx.fixture.createContract(org.id, {
      address,
      name: 'Test Contract',
    });

    expect(contract.id).toBeTruthy();
    expect(contract.address).toBe(address.toLowerCase());
    expect(contract.org_id).toBe(org.id);
    expect(contract.name).toBe('Test Contract');
  });

  test('updates contract name', async () => {
    const org = await ctx.fixture.createOrg('updateorg');
    const address = ctx.contractAddress();

    await ctx.fixture.createContract(org.id, { address });

    const updated = await ctx.rbac.updateContract(org.id, address, {
      name: 'Updated Name',
    });

    expect(updated.name).toBe('Updated Name');
  });

  test('updates contract metadata', async () => {
    const org = await ctx.fixture.createOrg('metaorg');
    const address = ctx.contractAddress();

    await ctx.fixture.createContract(org.id, { address });

    const updated = await ctx.rbac.updateContract(org.id, address, {
      metadata: { symbol: 'MTK', version: '1.0' },
    });

    expect(updated.metadata).toEqual({ symbol: 'MTK', version: '1.0' });
  });

  test('lists contracts in organization', async () => {
    const org = await ctx.fixture.createOrg('listorg');

    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);

    const contracts = await ctx.rbac.listContracts(org.id);

    expect(contracts.length).toBeGreaterThanOrEqual(2);
    const addresses = contracts.map((c) => c.address);
    expect(addresses).toContain(contract1.address);
    expect(addresses).toContain(contract2.address);
  });

  test('deletes contract', async () => {
    const org = await ctx.fixture.createOrg('deleteorg');
    const address = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, { address });

    // Verify it exists
    let contracts = await ctx.rbac.listContracts(org.id);
    expect(contracts.map((c) => c.address)).toContain(address.toLowerCase());

    // Delete it
    await ctx.rbac.deleteContract(org.id, address);

    // Verify it's gone
    contracts = await ctx.rbac.listContracts(org.id);
    expect(contracts.map((c) => c.address)).not.toContain(address.toLowerCase());
  });

  test('creates multiple contracts', async () => {
    const org = await ctx.fixture.createOrg('multicontractorg');

    const contract1 = await ctx.fixture.createContract(org.id);
    const contract2 = await ctx.fixture.createContract(org.id);
    const contract3 = await ctx.fixture.createContract(org.id);

    const contracts = await ctx.rbac.listContracts(org.id);
    const addresses = contracts.map((c) => c.address);

    expect(addresses).toContain(contract1.address);
    expect(addresses).toContain(contract2.address);
    expect(addresses).toContain(contract3.address);
  });

  test('contract address is stored lowercase', async () => {
    const org = await ctx.fixture.createOrg('caseorg');
    const address = '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12';

    const contract = await ctx.rbac.createContract(org.id, { address });

    // Address should be stored lowercase
    expect(contract.address).toBe(address.toLowerCase());

    // Cleanup
    await ctx.rbac.deleteContract(org.id, contract.address);
  });

  test('creates contract grant for group', async () => {
    const org = await ctx.fixture.createOrg('grantorg');
    const group = await ctx.fixture.createGroup(org.id, 'grantgroup');
    const contract = await ctx.fixture.createContract(org.id);

    const grant = await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read', 'write'],
    });

    expect(grant.contract_id).toBe(contract.id);
    expect(grant.group_id).toBe(group.id);
    expect(grant.claims).toContain('read');
    expect(grant.claims).toContain('write');
  });

  test('lists contract grants', async () => {
    const org = await ctx.fixture.createOrg('listgrantorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'grantgroup1');
    const group2 = await ctx.fixture.createGroup(org.id, 'grantgroup2');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group1.id,
      claims: ['read'],
    });
    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group2.id,
      claims: ['write'],
    });

    const grants = await ctx.rbac.listContractGrants(org.id, contract.address);

    expect(grants.length).toBe(2);
    const groupIds = grants.map((g) => g.group_id);
    expect(groupIds).toContain(group1.id);
    expect(groupIds).toContain(group2.id);
  });

  test('deletes contract grant', async () => {
    const org = await ctx.fixture.createOrg('deletegrantorg');
    const group = await ctx.fixture.createGroup(org.id, 'deletegrantgroup');
    const contract = await ctx.fixture.createContract(org.id);

    await ctx.rbac.createContractGrant(org.id, contract.address, {
      group_id: group.id,
      claims: ['read'],
    });

    // Verify grant exists
    let grants = await ctx.rbac.listContractGrants(org.id, contract.address);
    expect(grants.length).toBe(1);

    // Delete grant
    await ctx.rbac.deleteContractGrant(org.id, contract.address, group.id);

    // Verify it's gone
    grants = await ctx.rbac.listContractGrants(org.id, contract.address);
    expect(grants.length).toBe(0);
  });
});
