import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';
import ContractGrantForm from '../ContractGrantForm';
import { rbacApi } from '@/api/rbac';
import type { ContractGrant, Group } from '@/types/rbac';

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

function renderForm(props?: Partial<ComponentProps<typeof ContractGrantForm>>) {
  const onClose = vi.fn();
  const onSave = vi.fn();

  render(
    <ContractGrantForm
      orgId="org-1"
      contractAddress="0x1111111111111111111111111111111111111111"
      groups={mockGroups}
      existingGrantGroupIds={[]}
      onClose={onClose}
      onSave={onSave}
      {...props}
    />
  );

  return { onClose, onSave };
}

function mockGrantResponse(grant?: Partial<ContractGrant>) {
  return {
    data: {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: grant?.group_id || 'group-1',
      functions: grant?.functions ?? null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  } as Awaited<ReturnType<typeof rbacApi.contracts.createGrant>>;
}

describe('ContractGrantForm', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows validation error when submitting without selecting a group', async () => {
    renderForm();

    expect(screen.getByRole('button', { name: 'Add Group Access' })).toBeDisabled();
  });

  it('requires at least one selector in specific mode', async () => {
    const user = userEvent.setup();
    renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));
    await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

    expect(
      screen.getByText('Please add at least one function selector, or select "All functions"')
    ).toBeInTheDocument();
  });

  it('creates a grant with selected function rules', async () => {
    const user = userEvent.setup();
    const createGrantSpy = vi
      .spyOn(rbacApi.contracts, 'createGrant')
      .mockResolvedValue(mockGrantResponse());
    const { onSave } = renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));
    await user.click(screen.getByRole('button', { name: /balanceOf/ }));
    await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

    await waitFor(() => {
      expect(createGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        {
          group_id: 'group-1',
          functions: [{ selector: '0x70a08231' }],
        }
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
  });

  it('adds param_rules when self-address constraint is enabled', async () => {
    const user = userEvent.setup();
    const createGrantSpy = vi
      .spyOn(rbacApi.contracts, 'createGrant')
      .mockResolvedValue(mockGrantResponse());
    renderForm();

    await user.selectOptions(screen.getByRole('combobox'), 'group-1');
    await user.click(screen.getByRole('radio', { name: /Specific functions only/i }));
    await user.click(screen.getByRole('button', { name: /balanceOf/ }));
    await user.click(screen.getByLabelText(/account.*must be caller's own address/i));
    await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

    await waitFor(() => {
      expect(createGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        {
          group_id: 'group-1',
          functions: [
            {
              selector: '0x70a08231',
              param_rules: [{ index: 0, must_be: 'self' }],
            },
          ],
        }
      );
    });
  });

  it('updates an existing grant in edit mode', async () => {
    const user = userEvent.setup();
    const updateGrantSpy = vi
      .spyOn(rbacApi.contracts, 'updateGrant')
      .mockResolvedValue(mockGrantResponse({ group_id: 'group-2', functions: null }));
    const { onSave } = renderForm({
      grant: {
        id: 'grant-2',
        contract_id: 'contract-1',
        group_id: 'group-2',
        functions: [{ selector: '0x70a08231' }],
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      },
    });

    expect(screen.getByRole('combobox')).toBeDisabled();
    await user.click(screen.getByRole('radio', { name: /All functions/i }));
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));

    await waitFor(() => {
      expect(updateGrantSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111',
        'group-2',
        { functions: null }
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
  });
});
