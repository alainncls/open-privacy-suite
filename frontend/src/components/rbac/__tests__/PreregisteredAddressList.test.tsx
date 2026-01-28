import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockPreregisteredAddress,
  mockPreregisteredAddressUsed,
  mockPreregisteredAddresses,
} from '@/test/mocks/handlers';
import type { PreregisteredAddress } from '@/types/rbac';

// Mock the useOrgContext hook from RBACManager
vi.mock('../RBACManager', () => ({
  useOrgContext: () => ({
    selectedOrg: {
      id: 'org-1',
      slug: 'test-org',
      name: 'Test Organization',
      settings: {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    setSelectedOrg: vi.fn(),
    organizations: [{
      id: 'org-1',
      slug: 'test-org',
      name: 'Test Organization',
      settings: {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }],
    refreshOrgs: vi.fn(),
  }),
}));

// Import after mock is set up
import PreregisteredAddressList from '../PreregisteredAddressList';

describe('PreregisteredAddressList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', () => {
      // Make the request hang to see loading state
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', async () => {
          await new Promise(() => {}); // Never resolves
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      // Should show loading spinner (Loader2 icon with animate-spin)
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
    });

    it('shows "Pre-registered Addresses" heading', async () => {
      renderWithRBACContext(<PreregisteredAddressList />);

      expect(screen.getByText('Pre-registered Addresses')).toBeInTheDocument();
    });

    it('shows description text', async () => {
      renderWithRBACContext(<PreregisteredAddressList />);

      expect(screen.getByText('CREATE3 addresses whitelisted for future deployments')).toBeInTheDocument();
    });

    it('shows empty state when no addresses', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('No pre-registered addresses')).toBeInTheDocument();
      });

      expect(
        screen.getByText('Pre-register CREATE3 addresses to whitelist future deployment targets')
      ).toBeInTheDocument();
    });

    it('displays table with headers', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json(mockPreregisteredAddresses);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Address')).toBeInTheDocument();
      });

      expect(screen.getByText('Factory')).toBeInTheDocument();
      expect(screen.getByText('Salt')).toBeInTheDocument();
      expect(screen.getByText('Note')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Actions')).toBeInTheDocument();
    });
  });

  describe('Data Display', () => {
    it('shows address (possibly truncated)', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        // Address is truncated to first 8 chars + ... + last 6 chars
        expect(screen.getByText(/0xabcdef.*ef12/)).toBeInTheDocument();
      });
    });

    it('shows factory address (truncated)', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        // Factory address is also truncated
        expect(screen.getByText(/0x123456.*567890/)).toBeInTheDocument();
      });
    });

    it('shows note if present', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
      });
    });

    it('shows "-" when note is missing', async () => {
      const addressNoNote: PreregisteredAddress = {
        ...mockPreregisteredAddress,
        id: 'preregistered-no-note',
        note: undefined,
      };

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([addressNoNote]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        // The component shows '-' for undefined notes
        const noteCell = screen.getAllByText('-');
        expect(noteCell.length).toBeGreaterThan(0);
      });
    });

    it('shows "Pending" status for unused addresses', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Pending')).toBeInTheDocument();
      });
    });

    it('shows "Used" status for used addresses', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddressUsed]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Used')).toBeInTheDocument();
      });
    });

    it('formats created date correctly', async () => {
      const addressWithDate: PreregisteredAddress = {
        ...mockPreregisteredAddress,
        id: 'preregistered-date-test',
        created_at: '2024-03-15T10:30:00Z',
      };

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([addressWithDate]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        // The date is formatted as "Mar 15, 2024"
        expect(screen.getByText('Mar 15, 2024')).toBeInTheDocument();
      });
    });

    it('shows correct number of rows', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json(mockPreregisteredAddresses);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
      });

      // mockPreregisteredAddresses has 2 addresses
      expect(screen.getByText('Used preregistered address')).toBeInTheDocument();
    });
  });

  describe('Actions', () => {
    it('"Pre-register Addresses" button opens form dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        }),
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({
            address: '0x1234567890123456789012345678901234567890',
            deployed: true,
          });
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Pre-register Addresses')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Pre-register Addresses'));

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Pre-register CREATE3 Addresses' })).toBeInTheDocument();
      });

      // Form should be visible
      expect(screen.getByText('Factory Address')).toBeInTheDocument();
    });

    it('Delete button shows confirmation dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
      });

      // Find and click the delete button (trash icon)
      const deleteButton = screen.getByTitle('Delete pre-registered address');
      await user.click(deleteButton);

      // Confirmation dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Pre-registered Address')).toBeInTheDocument();
      });
      expect(screen.getByText(/Are you sure you want to delete/)).toBeInTheDocument();
    });

    it('Delete success removes from list', async () => {
      const user = userEvent.setup();

      let deleted = false;
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          if (deleted) {
            return HttpResponse.json([]);
          }
          return HttpResponse.json([mockPreregisteredAddress]);
        }),
        http.delete('/api/v1/orgs/:orgId/addresses/preregistered/:address', () => {
          deleted = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete pre-registered address');
      await user.click(deleteButton);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Pre-registered Address')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      await waitFor(() => {
        expect(screen.getByText('No pre-registered addresses')).toBeInTheDocument();
      });
    });

    it('Delete failure shows error dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        }),
        http.delete('/api/v1/orgs/:orgId/addresses/preregistered/:address', () => {
          return HttpResponse.json(
            { error: 'Cannot delete address' },
            { status: 500 }
          );
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete pre-registered address');
      await user.click(deleteButton);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Pre-registered Address')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Error dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText('Failed to delete pre-registered address.')).toBeInTheDocument();
    });

    it('Delete button is disabled for used addresses', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddressUsed]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Used preregistered address')).toBeInTheDocument();
      });

      // Find the delete button (should be disabled for used addresses)
      const deleteButton = screen.getByTitle('Delete pre-registered address');
      expect(deleteButton).toBeDisabled();
    });

    it('Empty state button opens form dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([]);
        }),
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({
            address: '0x1234567890123456789012345678901234567890',
            deployed: true,
          });
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(
          screen.getByText('Pre-register your first addresses')
        ).toBeInTheDocument();
      });

      await user.click(screen.getByText('Pre-register your first addresses'));

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Pre-register CREATE3 Addresses' })).toBeInTheDocument();
      });
    });

    it('Cancel in delete confirmation closes dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete pre-registered address');
      await user.click(deleteButton);

      // Wait for confirmation dialog
      await waitFor(() => {
        expect(screen.getByText('Delete Pre-registered Address')).toBeInTheDocument();
      });

      // Click Cancel
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      // Dialog should close
      await waitFor(() => {
        expect(screen.queryByText('Delete Pre-registered Address')).not.toBeInTheDocument();
      });

      // Address should still be in the list
      expect(screen.getByText('Test preregistered address')).toBeInTheDocument();
    });
  });

  describe('Form Integration', () => {
    it('refreshes list after successful form submission', async () => {
      const user = userEvent.setup();

      let submitCount = 0;
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          if (submitCount > 0) {
            return HttpResponse.json([
              ...mockPreregisteredAddresses,
              {
                id: 'preregistered-new-0',
                org_id: 'org-1',
                address: '0xnewaddress1234567890newaddress12345678',
                factory: '0x1234567890123456789012345678901234567890',
                salt: '0xnewsalt',
                note: 'New address',
                created_at: new Date().toISOString(),
                used_at: null,
              },
            ]);
          }
          return HttpResponse.json(mockPreregisteredAddresses);
        }),
        http.post('/api/v1/orgs/:orgId/addresses/preregister', async () => {
          submitCount++;
          return HttpResponse.json({
            addresses: [{
              id: 'preregistered-new-0',
              org_id: 'org-1',
              address: '0xnewaddress1234567890newaddress12345678',
              factory: '0x1234567890123456789012345678901234567890',
              salt: '0xnewsalt',
              note: 'New address',
              created_at: new Date().toISOString(),
              used_at: null,
            }],
          });
        }),
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({
            address: '0x1234567890123456789012345678901234567890',
            deployed: true,
          });
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Pre-register Addresses')).toBeInTheDocument();
      });

      // Open form
      await user.click(screen.getByText('Pre-register Addresses'));

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Fill form (factory is pre-filled in dev mode)
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'newsalt');

      // Submit form
      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      // After form submission, list should refresh and show new address
      await waitFor(() => {
        expect(screen.getByText('New address')).toBeInTheDocument();
      });
    });

    it('closes form dialog when Cancel is clicked', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json([mockPreregisteredAddress]);
        }),
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({
            address: '0x1234567890123456789012345678901234567890',
            deployed: true,
          });
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      await waitFor(() => {
        expect(screen.getByText('Pre-register Addresses')).toBeInTheDocument();
      });

      // Open form
      await user.click(screen.getByText('Pre-register Addresses'));

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Pre-register CREATE3 Addresses' })).toBeInTheDocument();
      });

      // Click Cancel in the form
      const cancelButton = screen.getByRole('button', { name: /Cancel/ });
      await user.click(cancelButton);

      // Dialog should close
      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Pre-register CREATE3 Addresses' })).not.toBeInTheDocument();
      });
    });
  });

  describe('Error States', () => {
    it('handles API error gracefully', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/addresses/preregistered', () => {
          return HttpResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
          );
        })
      );

      renderWithRBACContext(<PreregisteredAddressList />);

      // Should show empty state on error (component catches and shows empty array)
      await waitFor(() => {
        expect(screen.getByText('No pre-registered addresses')).toBeInTheDocument();
      });
    });
  });
});
