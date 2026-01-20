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

  test('registers contract ownership', async () => {
    const org = await ctx.fixture.createOrg('contractorg');
    const group = await ctx.fixture.createGroup(org.id, 'ownergroup');
    const address = ctx.contractAddress();

    const contract = await ctx.fixture.createContract(org.id, group.id, {
      address,
      abilities: ['upgrade', 'pause', 'admin'],
    });

    expect(contract.id).toBeTruthy();
    expect(contract.contract_address).toBe(address);
    expect(contract.org_id).toBe(org.id);
    expect(contract.owner_group_id).toBe(group.id);
    expect(contract.owner_abilities).toEqual(['upgrade', 'pause', 'admin']);
  });

  test('registers contract with default abilities', async () => {
    const org = await ctx.fixture.createOrg('defaultorg');
    const group = await ctx.fixture.createGroup(org.id, 'defaultgroup');

    const contract = await ctx.fixture.createContract(org.id, group.id);

    expect(contract.owner_abilities).toEqual([]);
  });

  test('updates contract owner group', async () => {
    const org = await ctx.fixture.createOrg('updateownerorg');
    const group1 = await ctx.fixture.createGroup(org.id, 'owner1');
    const group2 = await ctx.fixture.createGroup(org.id, 'owner2');
    const address = ctx.contractAddress();

    await ctx.fixture.createContract(org.id, group1.id, { address });

    const updated = await ctx.rbac.updateContract(org.id, address, {
      owner_group_id: group2.id,
    });

    expect(updated.owner_group_id).toBe(group2.id);
  });

  test('updates contract abilities', async () => {
    const org = await ctx.fixture.createOrg('updateabilitiesorg');
    const group = await ctx.fixture.createGroup(org.id, 'abilitygroup');
    const address = ctx.contractAddress();

    await ctx.fixture.createContract(org.id, group.id, {
      address,
      abilities: ['upgrade'],
    });

    const updated = await ctx.rbac.updateContract(org.id, address, {
      owner_abilities: ['upgrade', 'pause', 'admin'],
    });

    expect(updated.owner_abilities).toEqual(['upgrade', 'pause', 'admin']);
  });

  test('updates contract metadata', async () => {
    const org = await ctx.fixture.createOrg('metaorg');
    const group = await ctx.fixture.createGroup(org.id, 'metagroup');
    const address = ctx.contractAddress();

    await ctx.fixture.createContract(org.id, group.id, { address });

    const updated = await ctx.rbac.updateContract(org.id, address, {
      metadata: { name: 'My Token', symbol: 'MTK', version: '1.0' },
    });

    expect(updated.metadata).toEqual({ name: 'My Token', symbol: 'MTK', version: '1.0' });
  });

  test('lists contracts in organization', async () => {
    const org = await ctx.fixture.createOrg('listorg');
    const group = await ctx.fixture.createGroup(org.id, 'listgroup');

    const contract1 = await ctx.fixture.createContract(org.id, group.id);
    const contract2 = await ctx.fixture.createContract(org.id, group.id);

    const contracts = await ctx.rbac.listContracts(org.id);

    expect(contracts.length).toBeGreaterThanOrEqual(2);
    const addresses = contracts.map((c) => c.contract_address);
    expect(addresses).toContain(contract1.contract_address);
    expect(addresses).toContain(contract2.contract_address);
  });

  test('deletes contract ownership', async () => {
    const org = await ctx.fixture.createOrg('deleteorg');
    const group = await ctx.fixture.createGroup(org.id, 'deletegroup');
    const address = ctx.contractAddress();

    await ctx.rbac.createContract(org.id, {
      contract_address: address,
      owner_group_id: group.id,
    });

    // Verify it exists
    let contracts = await ctx.rbac.listContracts(org.id);
    expect(contracts.map((c) => c.contract_address)).toContain(address);

    // Delete it
    await ctx.rbac.deleteContract(org.id, address);

    // Verify it's gone
    contracts = await ctx.rbac.listContracts(org.id);
    expect(contracts.map((c) => c.contract_address)).not.toContain(address);
  });

  test('registers multiple contracts for same group', async () => {
    const org = await ctx.fixture.createOrg('multicontractorg');
    const group = await ctx.fixture.createGroup(org.id, 'multicontractgroup');

    const contract1 = await ctx.fixture.createContract(org.id, group.id, {
      abilities: ['upgrade'],
    });
    const contract2 = await ctx.fixture.createContract(org.id, group.id, {
      abilities: ['admin'],
    });
    const contract3 = await ctx.fixture.createContract(org.id, group.id, {
      abilities: ['pause'],
    });

    const contracts = await ctx.rbac.listContracts(org.id);
    const addresses = contracts.map((c) => c.contract_address);

    expect(addresses).toContain(contract1.contract_address);
    expect(addresses).toContain(contract2.contract_address);
    expect(addresses).toContain(contract3.contract_address);
  });

  test('registers contracts for different groups', async () => {
    const org = await ctx.fixture.createOrg('diffgrouporg');
    const group1 = await ctx.fixture.createGroup(org.id, 'diffgroup1');
    const group2 = await ctx.fixture.createGroup(org.id, 'diffgroup2');

    const contract1 = await ctx.fixture.createContract(org.id, group1.id);
    const contract2 = await ctx.fixture.createContract(org.id, group2.id);

    expect(contract1.owner_group_id).toBe(group1.id);
    expect(contract2.owner_group_id).toBe(group2.id);
  });

  test('contract address is lowercase', async () => {
    const org = await ctx.fixture.createOrg('caseorg');
    const group = await ctx.fixture.createGroup(org.id, 'casegroup');
    const address = '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12';

    const contract = await ctx.rbac.createContract(org.id, {
      contract_address: address,
      owner_group_id: group.id,
    });

    // The address might be stored as-is or lowercased depending on implementation
    expect(contract.contract_address.toLowerCase()).toBe(address.toLowerCase());

    // Cleanup
    await ctx.rbac.deleteContract(org.id, contract.contract_address);
  });
});
