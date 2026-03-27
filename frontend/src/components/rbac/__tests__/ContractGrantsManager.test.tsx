import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import ContractGrantsManager from '../ContractGrantsManager';
import { rbacApi } from '@/api/rbac';
import type { Contract, ContractGrant, Group, GroupAccess, GroupWithAccess, Claim } from '@/types/rbac';

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

const mockContract: Contract = {
  id: 'contract-1',
  org_id: 'org-1',
  address: '0x1111111111111111111111111111111111111111',
  name: 'Token Contract',
  deployed_by_user_id: null,
  deployed_at: null,
  metadata: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

const mockGroups: Group[] = [
  {
    id: 'group-1',
    org_id: 'org-1',
    slug: 'auditors',
    name: 'Auditors',
    description: 'Audit group',
    depth: 1,
    path: 'root.auditors',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'group-2',
    org_id: 'org-1',
    slug: 'ops',
    name: 'Ops',
    description: 'Operations group',
    depth: 1,
    path: 'root.ops',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
];

const mockGroupAccess: GroupAccess = {
  id: 'access-1',
  group_id: 'group-1',
  allowed_methods: ['eth_call'],
  claims: ['read'] as Claim[],
  rate_limit_rps: 100,
  rate_limit_daily: 10000,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/** Build an axios-like response wrapper used by vi.spyOn mocks. */
function axiosRes<T>(data: T) {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  };
}

function groupsResponse(groups: Group[] = mockGroups): GroupWithAccess[] {
  return groups.map(g => ({
    group: g,
    access: g.id === 'group-1' ? mockGroupAccess : null,
  }));
}

function stubApis(grants: ContractGrant[]) {
  vi.spyOn(rbacApi.contracts, 'listGrants').mockResolvedValue(
    axiosRes(grants) as Awaited<ReturnType<typeof rbacApi.contracts.listGrants>>
  );
  vi.spyOn(rbacApi.groups, 'list').mockResolvedValue(
    axiosRes({ data: groupsResponse(), total: mockGroups.length, limit: 50, offset: 0 }) as Awaited<
      ReturnType<typeof rbacApi.groups.list>
    >
  );
}

function renderManager(contract: Contract = mockContract) {
  return render(
    <ContractGrantsManager orgId="org-1" contract={contract} />
  );
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

describe('ContractGrantsManager — event rules display', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows "All events visible" when grant has no event_rules', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    expect(screen.getByText('All events visible')).toBeInTheDocument();
  });

  it('shows "All events visible" when event_rules is an empty array', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    expect(screen.getByText('All events visible')).toBeInTheDocument();
  });

  it('displays event rule names as violet pills', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
        },
        {
          topic0: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
          name: 'Approval',
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    // Event names should be rendered
    expect(screen.getByText('Transfer')).toBeInTheDocument();
    expect(screen.getByText('Approval')).toBeInTheDocument();

    // "All events visible" should NOT be shown
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();

    // The pills should have violet styling (bg-violet-100)
    const transferPill = screen.getByText('Transfer').closest('span');
    expect(transferPill?.className).toContain('bg-violet-100');
    expect(transferPill?.className).toContain('text-violet-800');
  });

  it('displays param constraints on event rule pills', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
          param_rules: [{ index: 0, must_be: 'self' }],
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    // Event name
    expect(screen.getByText('Transfer')).toBeInTheDocument();

    // Param constraint annotation: [param[0]=self]
    expect(screen.getByText('[param[0]=self]')).toBeInTheDocument();
  });

  it('displays multiple param constraints on a single event', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
          param_rules: [
            { index: 0, must_be: 'self' },
            { index: 1, must_be: 'self' },
          ],
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Transfer')).toBeInTheDocument();
    });

    // Should show both param constraints joined
    expect(screen.getByText('[param[0]=self, param[1]=self]')).toBeInTheDocument();
  });

  it('shows both function rules and event rules on the same grant', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: [{ selector: '0x70a08231' }],
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    // Function rule displayed (the component resolves 0x70a08231 to "balanceOf")
    expect(screen.getByText('balanceOf')).toBeInTheDocument();

    // Event rule displayed
    expect(screen.getByText('Transfer')).toBeInTheDocument();

    // Neither "All functions" nor "All events" should appear
    expect(screen.queryByText('All functions allowed')).not.toBeInTheDocument();
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();
  });

  it('backward compat: grant without event_rules field shows "All events visible"', async () => {
    // Simulate a legacy grant that predates event_rules — the field is undefined
    const legacyGrant = {
      id: 'grant-legacy',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    } as ContractGrant; // event_rules missing entirely
    stubApis([legacyGrant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    expect(screen.getByText('All events visible')).toBeInTheDocument();
  });

  it('event rule pill has tooltip with topic0 hash', async () => {
    const topic0 = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [{ topic0, name: 'Transfer' }],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Transfer')).toBeInTheDocument();
    });

    // The pill has a title attribute like "Transfer — 0xddf252ad..."
    const pill = screen.getByTitle(`Transfer — ${topic0}`);
    expect(pill).toBeInTheDocument();
  });
});
