import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';
import ContractGrantForm from '../ContractGrantForm';
import { rbacApi } from '@/api/rbac';
import type { ContractGrant, Group, EventSignature } from '@/types/rbac';

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

const mockEvents: EventSignature[] = [
  {
    name: 'Transfer',
    signature: 'Transfer(address,address,uint256)',
    topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
    inputs: [
      { name: 'from', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false },
    ],
  },
  {
    name: 'Approval',
    signature: 'Approval(address,address,uint256)',
    topic0: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
    inputs: [
      { name: 'owner', type: 'address', indexed: true },
      { name: 'spender', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false },
    ],
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
      event_rules: grant?.event_rules ?? null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  } as Awaited<ReturnType<typeof rbacApi.contracts.createGrant>>;
}

/** Stub listEvents so the component's useEffect resolves without hitting the network. */
function stubListEvents(events: EventSignature[] = []) {
  return vi.spyOn(rbacApi.contracts, 'listEvents').mockResolvedValue({
    data: { events },
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  } as Awaited<ReturnType<typeof rbacApi.contracts.listEvents>>);
}

describe('ContractGrantForm', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows validation error when submitting without selecting a group', async () => {
    stubListEvents();
    renderForm();

    expect(screen.getByRole('button', { name: 'Add Group Access' })).toBeDisabled();
  });

  it('requires at least one selector in specific mode', async () => {
    const user = userEvent.setup();
    stubListEvents();
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
    stubListEvents();
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
          event_rules: null,
        }
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
  });

  it('adds param_rules when self-address constraint is enabled', async () => {
    const user = userEvent.setup();
    stubListEvents();
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
          event_rules: null,
        }
      );
    });
  });

  it('updates an existing grant in edit mode', async () => {
    const user = userEvent.setup();
    stubListEvents();
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
        { functions: null, event_rules: null }
      );
      expect(onSave).toHaveBeenCalledTimes(1);
    });
  });

  // ===========================================================================
  // Event Rules
  // ===========================================================================

  describe('Event Rules', () => {
    it('defaults to "All events visible" mode', async () => {
      stubListEvents();
      renderForm();

      const allEventsRadio = screen.getByRole('radio', { name: /All events visible/i });
      expect(allEventsRadio).toBeChecked();
    });

    it('shows event picker when switching to "Specific events only"', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      // Initially no "Visible events" or event picker
      expect(screen.queryByText('Visible events:')).not.toBeInTheDocument();

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Should now show the ABI events section
      await waitFor(() => {
        expect(screen.getByText(/Contract events/)).toBeInTheDocument();
      });
    });

    it('fetches events from the API and displays them', async () => {
      const user = userEvent.setup();
      const listEventsSpy = stubListEvents(mockEvents);
      renderForm();

      // Verify API was called
      expect(listEventsSpy).toHaveBeenCalledWith(
        'org-1',
        '0x1111111111111111111111111111111111111111'
      );

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Both events should appear in the picker
      await waitFor(() => {
        expect(screen.getByText('Transfer')).toBeInTheDocument();
        expect(screen.getByText('Approval')).toBeInTheDocument();
      });
    });

    it('shows warning when no ABI events are available', async () => {
      const user = userEvent.setup();
      stubListEvents([]); // No events
      renderForm();

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/No ABI uploaded for this contract.*Upload an ABI to configure event visibility rules/i)
        ).toBeInTheDocument();
      });
    });

    it('adds and removes events from the selected list', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Wait for events to load, then click Transfer to add it
      await waitFor(() => {
        expect(screen.getByText('Transfer')).toBeInTheDocument();
      });

      // Click the Transfer button in the picker to add it
      await user.click(screen.getByRole('button', { name: /Transfer/ }));

      // Should appear in the "Visible events" list
      expect(screen.getByText('Visible events:')).toBeInTheDocument();

      // The Transfer button in the picker should now be disabled (already added)
      const transferButtons = screen.getAllByRole('button', { name: /Transfer/ });
      const pickerButton = transferButtons.find(b => b.hasAttribute('disabled'));
      expect(pickerButton).toBeTruthy();

      // Remove it by clicking the X button next to the selected event
      // The remove button is inside the selected event rule's container
      const removeButtons = screen.getAllByRole('button').filter(
        b => b.querySelector('svg.w-3.h-3')
      );
      // Click the last remove-like button (the X on the event rule)
      const eventRuleContainer = screen.getByText('Visible events:').parentElement;
      const removeBtn = eventRuleContainer?.querySelector('button[type="button"]:last-of-type');
      if (removeBtn) {
        await user.click(removeBtn);
      }

      // "Visible events:" label should be gone since no events selected
      expect(screen.queryByText('Visible events:')).not.toBeInTheDocument();
    });

    it('shows self-address checkbox for address-type event params', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Transfer/ })).toBeInTheDocument();
      });

      // Add Transfer event (has from:address and to:address params)
      await user.click(screen.getByRole('button', { name: /Transfer/ }));

      // Should show self-address checkboxes for the address-type params
      // Transfer event has from (index 0) and to (index 1) as address-type params
      await waitFor(() => {
        expect(screen.getByLabelText(/from.*must be caller's own address/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/to.*must be caller's own address/i)).toBeInTheDocument();
      });
    });

    it('requires at least one event when in specific mode', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      renderForm();

      await user.selectOptions(screen.getByRole('combobox'), 'group-1');
      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));
      // Don't add any events
      await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

      expect(
        screen.getByText('Please add at least one event, or select "All events visible"')
      ).toBeInTheDocument();
    });

    it('submits event_rules as null when "All events visible" is selected', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await user.selectOptions(screen.getByRole('combobox'), 'group-1');
      // Leave default "All events visible"
      await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: null,
          })
        );
      });
    });

    it('submits event_rules with selected events', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await user.selectOptions(screen.getByRole('combobox'), 'group-1');
      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      // Wait for events, then add Transfer
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Transfer/ })).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Transfer/ }));
      await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: [
              { topic0: mockEvents[0].topic0, name: 'Transfer' },
            ],
          })
        );
      });
    });

    it('submits event_rules with param_rules when self constraint is toggled', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const createGrantSpy = vi
        .spyOn(rbacApi.contracts, 'createGrant')
        .mockResolvedValue(mockGrantResponse());
      renderForm();

      await user.selectOptions(screen.getByRole('combobox'), 'group-1');
      await user.click(screen.getByRole('radio', { name: /Specific events only/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Transfer/ })).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Transfer/ }));

      // Check the "from must be caller's own address" checkbox
      // The event has address params: from (index 0) and to (index 1)
      await waitFor(() => {
        expect(screen.getByLabelText(/from.*must be caller's own address/i)).toBeInTheDocument();
      });
      await user.click(screen.getByLabelText(/from.*must be caller's own address/i));
      await user.click(screen.getByRole('button', { name: 'Add Group Access' }));

      await waitFor(() => {
        expect(createGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          expect.objectContaining({
            event_rules: [
              {
                topic0: mockEvents[0].topic0,
                name: 'Transfer',
                param_rules: [{ index: 0, must_be: 'self' }],
              },
            ],
          })
        );
      });
    });

    it('pre-populates event rules in edit mode', async () => {
      stubListEvents(mockEvents);
      renderForm({
        grant: {
          id: 'grant-edit',
          contract_id: 'contract-1',
          group_id: 'group-1',
          functions: null,
          event_rules: [
            { topic0: mockEvents[0].topic0, name: 'Transfer' },
          ],
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      });

      // Should be in "Specific events only" mode
      expect(screen.getByRole('radio', { name: /Specific events only/i })).toBeChecked();

      // Transfer should appear in the visible events list
      expect(screen.getByText('Visible events:')).toBeInTheDocument();
      expect(screen.getByText('Transfer')).toBeInTheDocument();
    });

    it('updates event_rules in edit mode', async () => {
      const user = userEvent.setup();
      stubListEvents(mockEvents);
      const updateGrantSpy = vi
        .spyOn(rbacApi.contracts, 'updateGrant')
        .mockResolvedValue(mockGrantResponse({ group_id: 'group-1' }));
      renderForm({
        grant: {
          id: 'grant-edit',
          contract_id: 'contract-1',
          group_id: 'group-1',
          functions: null,
          event_rules: [
            { topic0: mockEvents[0].topic0, name: 'Transfer' },
          ],
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      });

      // Switch to "All events visible"
      await user.click(screen.getByRole('radio', { name: /All events visible/i }));
      await user.click(screen.getByRole('button', { name: 'Save Changes' }));

      await waitFor(() => {
        expect(updateGrantSpy).toHaveBeenCalledWith(
          'org-1',
          '0x1111111111111111111111111111111111111111',
          'group-1',
          { functions: null, event_rules: null }
        );
      });
    });
  });
});
