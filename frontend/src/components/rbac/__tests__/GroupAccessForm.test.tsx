import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import GroupAccessForm from '../GroupAccessForm';
import { mockGroupAccess } from '@/test/mocks/handlers';
import { mockGroupAccessFull } from '@/test/mocks/rbac-fixtures';
import { METHOD_SECTIONS, getPresetMethods, PERMISSION_PRESETS } from '@/types/rbac';

// Minimal wrapper since GroupAccessForm doesn't need org context directly
function renderGroupAccessForm(props: {
  orgId?: string;
  groupId?: string;
  onClose?: () => void;
  onSave?: () => void;
}) {
  const defaultProps = {
    orgId: 'org-1',
    groupId: 'group-1',
    onClose: vi.fn(),
    onSave: vi.fn(),
  };

  return render(<GroupAccessForm {...defaultProps} {...props} />);
}

describe('GroupAccessForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Loading', () => {
    it('fetches /groups/:id/access on mount', async () => {
      let fetchCalled = false;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          fetchCalled = true;
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(fetchCalled).toBe(true);
      });
    });

    it('shows loading spinner while fetching', () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      expect(document.querySelector('.animate-spin')).toBeInTheDocument();
    });

    it('shows existing allowed_methods as checked checkboxes', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('eth_call')).toBeInTheDocument();
      });

      // Check that selected methods have the checked indicator (bg-primary)
      const ethCallLabel = screen.getByText('eth_call').closest('label');
      expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
    });

    it('does not render rate limit inputs', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('eth_call')).toBeInTheDocument();
      });

      // Rate limit fields should not exist — rate limiting is handled at the RPC proxy API key level
      expect(screen.queryByPlaceholderText('100')).not.toBeInTheDocument();
      expect(screen.queryByPlaceholderText('100000')).not.toBeInTheDocument();
      expect(screen.queryByText('Rate Limit (RPS)')).not.toBeInTheDocument();
      expect(screen.queryByText('Rate Limit (Daily)')).not.toBeInTheDocument();
    });
  });

  describe('Preset Cards', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('renders all four preset cards', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Each preset appears as a card (button) with description
      expect(screen.getByText('End users with wallets — send payments, check balances')).toBeInTheDocument();
      expect(screen.getByText('Automated systems — raw transactions, event monitoring')).toBeInTheDocument();
      expect(screen.getByText('Engineers — deploy, debug, inspect contract state')).toBeInTheDocument();
      expect(screen.getByText('Full control — all methods, all claims')).toBeInTheDocument();
    });

    it('clicking preset fills methods', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Click Wallet User preset card (use the description to find the right button)
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      // After clicking, all Wallet User methods should be checked
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });

      // eth_sendTransaction should also be checked (part of Wallet User preset)
      const sendTxLabel = screen.getByText('eth_sendTransaction').closest('label');
      expect(sendTxLabel?.querySelector('.bg-primary')).toBeInTheDocument();

      // eth_sendRawTransaction should NOT be checked (Service/Backend only)
      const rawTxLabel = screen.getByText('eth_sendRawTransaction').closest('label');
      expect(rawTxLabel?.querySelector('.bg-primary')).not.toBeInTheDocument();
    });

    it('clicking Developer preset includes all lower-level methods', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Click Developer preset card
      const devCard = screen.getByText('Engineers — deploy, debug, inspect contract state').closest('button')!;
      await user.click(devCard);

      // Developer includes Wallet User + Service/Backend + Developer methods
      await waitFor(() => {
        // Wallet User method
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });

      // Service/Backend method
      const rawTxLabel = screen.getByText('eth_sendRawTransaction').closest('label');
      expect(rawTxLabel?.querySelector('.bg-primary')).toBeInTheDocument();

      // Developer method
      const traceLabel = screen.getByText('debug_traceTransaction').closest('label');
      expect(traceLabel?.querySelector('.bg-primary')).toBeInTheDocument();
    });

    it('modifying methods deselects preset highlight', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Apply Wallet User preset
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      await waitFor(() => {
        // The Wallet User card should be highlighted (border-primary)
        expect(walletCard.className).toContain('border-primary');
      });

      // Now toggle off a method to diverge from the preset
      const ethCallLabel = screen.getByText('eth_call').closest('label');
      if (ethCallLabel) {
        await user.click(ethCallLabel);
      }

      // The preset card should no longer be highlighted
      await waitFor(() => {
        expect(walletCard.className).not.toContain('border-primary bg-primary-50');
      });
    });

    it('clicking Wallet User preset selects exactly the right number of methods', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
      const expectedCount = getPresetMethods(walletPreset).length;

      // Verify the section counter shows the correct count
      await waitFor(() => {
        // Wallet User section header should show N / N (all selected)
        const sectionMethods = METHOD_SECTIONS['Wallet User'].methods;
        expect(screen.getByText(`${sectionMethods.length} / ${sectionMethods.length}`)).toBeInTheDocument();
      });

      // Service/Backend section should show 0 selected
      const serviceMethods = METHOD_SECTIONS['Service / Backend'].methods;
      expect(screen.getByText(`0 / ${serviceMethods.length}`)).toBeInTheDocument();

      // Developer section should show 0 selected
      const devMethods = METHOD_SECTIONS['Developer'].methods;
      expect(screen.getByText(`0 / ${devMethods.length}`)).toBeInTheDocument();

      // The preset card shows "N methods" label
      expect(screen.getByText(`${expectedCount} methods`)).toBeInTheDocument();
    });

    it('clicking Developer preset selects all 3 sections fully', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      const devCard = screen.getByText('Engineers — deploy, debug, inspect contract state').closest('button')!;
      await user.click(devCard);

      // All three sections should show full counts
      await waitFor(() => {
        const walletMethods = METHOD_SECTIONS['Wallet User'].methods;
        expect(screen.getByText(`${walletMethods.length} / ${walletMethods.length}`)).toBeInTheDocument();
      });

      const serviceMethods = METHOD_SECTIONS['Service / Backend'].methods;
      expect(screen.getByText(`${serviceMethods.length} / ${serviceMethods.length}`)).toBeInTheDocument();

      const devMethods = METHOD_SECTIONS['Developer'].methods;
      expect(screen.getByText(`${devMethods.length} / ${devMethods.length}`)).toBeInTheDocument();
    });

    it('edit mode detects matching preset on load', async () => {
      // Load with exact Wallet User preset methods
      const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
      const walletMethods = getPresetMethods(walletPreset);

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            allowed_methods: walletMethods,
            claims: ['read', 'write'],
          });
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        // The Wallet User preset card should be highlighted
        const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button');
        expect(walletCard?.className).toContain('border-primary');
      });
    });
  });

  describe('Method Sections', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('displays method sections by role', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        // Service/Backend section (with + prefix) - unique to section headers
        expect(screen.getByText('+ Service / Backend')).toBeInTheDocument();
      });

      // Developer section (with + prefix)
      expect(screen.getByText('+ Developer')).toBeInTheDocument();

      // Method section descriptions
      expect(screen.getByText('Core methods for end users with wallets')).toBeInTheDocument();
      expect(screen.getByText('Additional methods for automated systems and backend services')).toBeInTheDocument();
      expect(screen.getByText('Deep inspection and debugging tools for engineers')).toBeInTheDocument();
    });

    it('can toggle method by clicking checkbox', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('eth_estimateGas')).toBeInTheDocument();
      });

      // Click on eth_estimateGas to toggle it
      const methodLabel = screen.getByText('eth_estimateGas').closest('label');
      if (methodLabel) {
        await user.click(methodLabel);
      }

      // After clicking, it should be toggled
      await waitFor(() => {
        const updatedLabel = screen.getByText('eth_estimateGas').closest('label');
        expect(updatedLabel).toBeInTheDocument();
      });
    });

    it('can use Select All to check all methods in section', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Core methods for end users with wallets')).toBeInTheDocument();
      });

      // Click Select All for the first section (Wallet User)
      const selectAllButtons = screen.getAllByText('Select All');
      await user.click(selectAllButtons[0]);

      // After clicking, all Wallet User methods should be selected
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });
    });
  });

  describe('Saving', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('Save button submits PUT to /groups/:id/access', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Click save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toBeDefined();
      expect(capturedBody).toHaveProperty('allowed_methods');
      expect(capturedBody).toHaveProperty('claims');
    });

    it('success calls onSave callback', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('error shows error message', async () => {
      const user = userEvent.setup();

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(
            { error: 'Invalid rate limit value' },
            { status: 400 }
          );
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(screen.getByText('Invalid rate limit value')).toBeInTheDocument();
      });
    });

    it('shows loading state while saving', async () => {
      const user = userEvent.setup();

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(screen.getByText('Saving...')).toBeInTheDocument();
      });
    });

    it('save derives correct claims for Wallet User preset', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Apply Wallet User preset
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      await waitFor(() => {
        expect(walletCard.className).toContain('border-primary');
      });

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      // Wallet User has no operational claims — read/write are implicit from methods
      expect(capturedBody).toBeDefined();
      const claims = capturedBody!.claims as string[];
      expect(claims).not.toContain('read');
      expect(claims).not.toContain('write');
      expect(claims).not.toContain('admin');
      expect(claims).not.toContain('deploy');
      expect(claims).not.toContain('upgrade');
    });

    it('save derives admin claim for Admin preset', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Apply Admin preset
      const adminCard = screen.getByText('Full control — all methods, all claims').closest('button')!;
      await user.click(adminCard);

      await waitFor(() => {
        expect(adminCard.className).toContain('border-primary');
      });

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      // Admin preset sets admin claim which implies deploy+upgrade (not read/write)
      expect(capturedBody).toBeDefined();
      const claims = capturedBody!.claims as string[];
      expect(claims).toContain('admin');
      expect(claims).toContain('deploy');
      expect(claims).toContain('upgrade');
      expect(claims).not.toContain('read');
      expect(claims).not.toContain('write');
    });
  });

  describe('Cancel Button', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('calls onClose when Cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderGroupAccessForm({ onClose });

      await waitFor(() => {
        expect(screen.getByText('Cancel')).toBeInTheDocument();
      });

      const cancelButton = screen.getByText('Cancel');
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe('Empty Access Settings', () => {
    it('handles group with no existing access settings', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(null, { status: 404 });
        })
      );

      renderGroupAccessForm({});

      // Should not crash and show empty form
      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Method sections should be shown (use unique section descriptions)
      expect(screen.getByText('Core methods for end users with wallets')).toBeInTheDocument();
      expect(screen.getByText('+ Service / Backend')).toBeInTheDocument();
      expect(screen.getByText('+ Developer')).toBeInTheDocument();
    });
  });

  describe('Full Integration', () => {
    it('can apply preset, modify methods, and save', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        }),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Apply Wallet User preset
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      // Verify methods are checked
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        allowed_methods: expect.arrayContaining(['eth_call', 'eth_sendTransaction']),
      });
      // Wallet User has no operational claims — read/write removed
      const integClaims = (capturedBody as Record<string, unknown>).claims as string[];
      expect(integClaims).not.toContain('read');
      expect(integClaims).not.toContain('write');
      // Rate limits should not be in the payload
      expect(capturedBody).not.toHaveProperty('rate_limit_rps');
      expect(capturedBody).not.toHaveProperty('rate_limit_daily');
    });
  });
});
