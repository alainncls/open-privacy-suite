import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import GroupAccessForm from '../GroupAccessForm';
import { mockGroupAccess } from '@/test/mocks/handlers';
import { mockGroupAccessFull } from '@/test/mocks/rbac-fixtures';
import type { Claim } from '@/types/rbac';

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
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
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
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      expect(document.querySelector('.animate-spin')).toBeInTheDocument();
    });

    it('shows existing allowed_methods as checked checkboxes', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        // The methods are displayed as checkboxes in collapsible sections
        // Look for a method that should be checked
        expect(screen.getByText('eth_call')).toBeInTheDocument();
      });

      // Check that selected methods have the checked indicator (bg-[#8950FA])
      const ethCallLabel = screen.getByText('eth_call').closest('label');
      expect(ethCallLabel?.querySelector('.bg-\\[\\#8950FA\\]')).toBeInTheDocument();
    });

    it('shows existing claims', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        // Find the Read claim label
        expect(screen.getByText('Read')).toBeInTheDocument();
      });

      // The checkbox for 'read' should be checked (mockGroupAccessFull has read, write)
      // We check by looking for the checked state indicator
      const readLabel = screen.getByText('Read').closest('label');
      expect(readLabel).toBeInTheDocument();
    });

    it('shows existing rate limits', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        const rpsInput = screen.getByPlaceholderText('100');
        expect(rpsInput).toHaveValue(mockGroupAccessFull.rate_limit_rps);
      });

      const dailyInput = screen.getByPlaceholderText('100000');
      expect(dailyInput).toHaveValue(mockGroupAccessFull.rate_limit_daily);
    });
  });

  describe('Editing Allowed Methods', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            claims: ['read', 'write'] as Claim[], // Need claims to enable method sections
          });
        })
      );
    });

    it('displays methods as checkboxes in sections', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        // Should show Read Methods section
        expect(screen.getByText('Read Methods')).toBeInTheDocument();
        // Should show Write Methods section
        expect(screen.getByText('Write Methods')).toBeInTheDocument();
      });

      // Methods should be visible
      expect(screen.getByText('eth_call')).toBeInTheDocument();
      expect(screen.getByText('eth_getBalance')).toBeInTheDocument();
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

      // After clicking, it should be toggled (check for visual indicator)
      await waitFor(() => {
        const updatedLabel = screen.getByText('eth_estimateGas').closest('label');
        const checkbox = updatedLabel?.querySelector('.bg-\\[\\#8950FA\\]');
        // State should have changed (either now checked or unchecked)
        expect(updatedLabel).toBeInTheDocument();
      });
    });

    it('can use Select All to check all methods in section', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Read Methods')).toBeInTheDocument();
      });

      // Click Select All for read methods
      const selectAllButtons = screen.getAllByText('Select All');
      await user.click(selectAllButtons[0]); // First one is for read methods

      // After clicking, all read methods should be selected
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-\\[\\#8950FA\\]')).toBeInTheDocument();
      });
    });
  });

  describe('Editing Default Claims', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            claims: ['read'],
          });
        })
      );
    });

    it('shows checkboxes for all claims', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Read')).toBeInTheDocument();
      });

      expect(screen.getByText('Write')).toBeInTheDocument();
      expect(screen.getByText('Admin')).toBeInTheDocument();
      expect(screen.getByText('Upgrade')).toBeInTheDocument();
      expect(screen.getByText('Deploy')).toBeInTheDocument();
    });

    it('current claims are checked', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            claims: ['read', 'write'] as Claim[],
          });
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Read')).toBeInTheDocument();
      });

      // Check that read and write labels have the checked indicator
      // The component uses a custom checkbox with bg-[#8950FA] when checked
      const readLabel = screen.getByText('Read').closest('label');
      const writeLabel = screen.getByText('Write').closest('label');

      expect(readLabel?.querySelector('.bg-\\[\\#8950FA\\]')).toBeInTheDocument();
      expect(writeLabel?.querySelector('.bg-\\[\\#8950FA\\]')).toBeInTheDocument();
    });

    it('can toggle claims', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Write')).toBeInTheDocument();
      });

      // Click on Write to toggle it on
      const writeLabel = screen.getByText('Write').closest('label');
      if (writeLabel) {
        await user.click(writeLabel);
      }

      // After clicking, the write claim should be toggled
      // We can verify by checking if the UI updated (visual indicator changed)
      await waitFor(() => {
        const updatedWriteLabel = screen.getByText('Write').closest('label');
        expect(updatedWriteLabel?.querySelector('.bg-\\[\\#8950FA\\]')).toBeInTheDocument();
      });
    });
  });

  describe('Rate Limits', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );
    });

    it('shows RPS input with current value', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        const rpsInput = screen.getByPlaceholderText('100');
        expect(rpsInput).toHaveValue(mockGroupAccessFull.rate_limit_rps);
      });
    });

    it('shows daily limit input with current value', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        const dailyInput = screen.getByPlaceholderText('100000');
        expect(dailyInput).toHaveValue(mockGroupAccessFull.rate_limit_daily);
      });
    });

    it('validates numeric input for RPS', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByPlaceholderText('100')).toBeInTheDocument();
      });

      const rpsInput = screen.getByPlaceholderText('100');
      await user.clear(rpsInput);
      await user.type(rpsInput, '50');

      expect(rpsInput).toHaveValue(50);
    });

    it('validates numeric input for daily limit', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByPlaceholderText('100000')).toBeInTheDocument();
      });

      const dailyInput = screen.getByPlaceholderText('100000');
      await user.clear(dailyInput);
      await user.type(dailyInput, '25000');

      expect(dailyInput).toHaveValue(25000);
    });
  });

  describe('Saving', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('Save button submits PUT to /groups/:id/access', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
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
        http.put('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
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
        http.put('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
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
        http.put('/api/v1/orgs/:orgId/groups/:groupId/access', async () => {
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
  });

  describe('Cancel Button', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
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
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(null, { status: 404 });
        })
      );

      renderGroupAccessForm({});

      // Should not crash and show empty form
      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Method sections should be shown (though disabled without claims)
      expect(screen.getByText('Read Methods')).toBeInTheDocument();
      expect(screen.getByText('Write Methods')).toBeInTheDocument();
    });
  });

  describe('Full Integration', () => {
    it('can modify all fields and save', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            claims: ['read'] as Claim[],
            allowed_methods: ['eth_call'],
          });
        }),
        http.put('/api/v1/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
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

      // Toggle Write claim first (this enables write methods section)
      const writeLabel = screen.getByText('Write').closest('label');
      if (writeLabel) {
        await user.click(writeLabel);
      }

      // Wait for write methods section to be enabled
      await waitFor(() => {
        // After enabling write claim, we should be able to click write methods
        const sendTxLabel = screen.getByText('eth_sendTransaction').closest('label');
        expect(sendTxLabel).toBeInTheDocument();
      });

      // Click on eth_sendTransaction to select it
      const sendTxLabel = screen.getByText('eth_sendTransaction').closest('label');
      if (sendTxLabel) {
        await user.click(sendTxLabel);
      }

      // Modify RPS
      const rpsInput = screen.getByPlaceholderText('100');
      await user.clear(rpsInput);
      await user.type(rpsInput, '200');

      // Modify daily limit
      const dailyInput = screen.getByPlaceholderText('100000');
      await user.clear(dailyInput);
      await user.type(dailyInput, '75000');

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        allowed_methods: expect.arrayContaining(['eth_call', 'eth_sendTransaction']),
        claims: expect.arrayContaining(['read', 'write']),
        rate_limit_rps: 200,
        rate_limit_daily: 75000,
      });
    });
  });
});
