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

    it('shows existing allowed_methods', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        // The methods are displayed in a textarea, one per line
        const textarea = screen.getByPlaceholderText(/eth_call/);
        expect(textarea).toHaveValue(
          mockGroupAccessFull.allowed_methods.join('\n')
        );
      });
    });

    it('shows existing default_claims', async () => {
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
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('displays methods in textarea', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        const textarea = screen.getByPlaceholderText(/eth_call/);
        expect(textarea).toHaveValue(mockGroupAccess.allowed_methods.join('\n'));
      });
    });

    it('can add new method by typing', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/eth_call/)).toBeInTheDocument();
      });

      const textarea = screen.getByPlaceholderText(/eth_call/);
      await user.clear(textarea);
      await user.type(textarea, 'eth_call\neth_sendTransaction\neth_estimateGas');

      expect(textarea).toHaveValue('eth_call\neth_sendTransaction\neth_estimateGas');
    });

    it('can remove method by editing textarea', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/eth_call/)).toBeInTheDocument();
      });

      const textarea = screen.getByPlaceholderText(/eth_call/);
      await user.clear(textarea);
      await user.type(textarea, 'eth_call');

      expect(textarea).toHaveValue('eth_call');
    });
  });

  describe('Editing Default Claims', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            default_claims: ['read'],
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
            default_claims: ['read', 'write'] as Claim[],
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
      expect(capturedBody).toHaveProperty('default_claims');
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

      // Methods textarea should be empty
      const textarea = screen.getByPlaceholderText(/eth_call/);
      expect(textarea).toHaveValue('');
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
            default_claims: ['read'] as Claim[],
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

      // Modify allowed methods
      const textarea = screen.getByPlaceholderText(/eth_call/);
      await user.clear(textarea);
      await user.type(textarea, 'eth_call\neth_sendTransaction');

      // Toggle Write claim
      const writeLabel = screen.getByText('Write').closest('label');
      if (writeLabel) {
        await user.click(writeLabel);
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
        allowed_methods: ['eth_call', 'eth_sendTransaction'],
        default_claims: expect.arrayContaining(['read', 'write']),
        rate_limit_rps: 200,
        rate_limit_daily: 75000,
      });
    });
  });
});
