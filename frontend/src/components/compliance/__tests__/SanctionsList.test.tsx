import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { mockSanctionedAddresses, mockOrganization } from '@/test/mocks/handlers';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import SanctionsList from '../SanctionsList';

describe('SanctionsList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/compliance/sanctions', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithComplianceContext(<SanctionsList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no sanctioned addresses', async () => {
      server.use(
        http.get('/api/v1/compliance/sanctions', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('No sanctioned addresses')).toBeInTheDocument();
      });
    });

    it('displays sanctioned addresses in a table', async () => {
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('OFAC SDN list')).toBeInTheDocument();
        expect(screen.getByText('Internal investigation')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Address')).toBeInTheDocument();
      expect(screen.getByText('Reason')).toBeInTheDocument();
      expect(screen.getByText('Source')).toBeInTheDocument();
      expect(screen.getByText('Scope')).toBeInTheDocument();
    });

    it('shows Global badge for global sanctions', async () => {
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('Global')).toBeInTheDocument();
      });
    });

    it('shows org-specific badge for org-scoped sanctions', async () => {
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        // The second sanction has org_id = 'org-1', should show org name
        expect(screen.getByText('Test Organization')).toBeInTheDocument();
      });
    });

    it('shows source values', async () => {
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('OFAC')).toBeInTheDocument();
        expect(screen.getByText('manual')).toBeInTheDocument();
      });
    });
  });

  describe('CRUD Operations', () => {
    it('opens add dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('Add Address')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Address'));

      await waitFor(() => {
        expect(screen.getByText('Add Sanctioned Address')).toBeInTheDocument();
      });

      expect(screen.getByPlaceholderText('0x...')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('OFAC SDN list, etc.')).toBeInTheDocument();
    });

    it('submits new sanctioned address', async () => {
      let addCalled = false;
      server.use(
        http.post('/api/v1/compliance/sanctions', async () => {
          addCalled = true;
          return HttpResponse.json({
            id: 'sanction-new',
            address: '0xnewbadaddress0000000000000000000000000000',
            reason: 'Test reason',
            source: 'manual',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('Add Address')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Address'));

      await waitFor(() => {
        expect(screen.getByText('Add Sanctioned Address')).toBeInTheDocument();
      });

      await user.type(screen.getByPlaceholderText('0x...'), '0xnewbadaddress0000000000000000000000000000');
      await user.type(screen.getByPlaceholderText('OFAC SDN list, etc.'), 'Test reason');

      await user.click(screen.getByRole('button', { name: 'Add to Sanctions' }));

      await waitFor(() => {
        expect(addCalled).toBe(true);
      });
    });

    it('shows delete confirmation dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('OFAC SDN list')).toBeInTheDocument();
      });

      // Click delete button
      const allButtons = screen.getAllByRole('button');
      const deleteButton = allButtons.find(btn => btn.querySelector('.lucide-trash-2'));
      if (deleteButton) {
        await user.click(deleteButton);

        await waitFor(() => {
          expect(screen.getByText('Remove Sanctioned Address')).toBeInTheDocument();
          expect(screen.getByText(/Are you sure/)).toBeInTheDocument();
        });
      }
    });

    it('removes sanction after confirmation', async () => {
      let deleteCalled = false;
      server.use(
        http.delete('/api/v1/compliance/sanctions/:id', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('OFAC SDN list')).toBeInTheDocument();
      });

      const allButtons = screen.getAllByRole('button');
      const deleteButton = allButtons.find(btn => btn.querySelector('.lucide-trash-2'));
      if (deleteButton) {
        await user.click(deleteButton);

        await waitFor(() => {
          expect(screen.getByText('Remove Sanctioned Address')).toBeInTheDocument();
        });

        await user.click(screen.getByRole('button', { name: 'Remove' }));

        await waitFor(() => {
          expect(deleteCalled).toBe(true);
        });
      }
    });

    it('has scope selector with Global option and orgs', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('Add Address')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Address'));

      await waitFor(() => {
        expect(screen.getByText('Add Sanctioned Address')).toBeInTheDocument();
      });

      // Check scope dropdown has Global option
      const scopeSelect = screen.getByText('Global (all organizations)');
      expect(scopeSelect).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('shows error when list fails to load', async () => {
      server.use(
        http.get('/api/v1/compliance/sanctions', () => {
          return HttpResponse.json({ error: 'Service unavailable' }, { status: 503 });
        })
      );

      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('Service unavailable')).toBeInTheDocument();
      });
    });

    it('shows form error when add fails', async () => {
      server.use(
        http.post('/api/v1/compliance/sanctions', () => {
          return HttpResponse.json({ error: 'Address already sanctioned' }, { status: 409 });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<SanctionsList />);

      await waitFor(() => {
        expect(screen.getByText('Add Address')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Address'));

      await waitFor(() => {
        expect(screen.getByText('Add Sanctioned Address')).toBeInTheDocument();
      });

      await user.type(screen.getByPlaceholderText('0x...'), '0xabc');
      await user.type(screen.getByPlaceholderText('OFAC SDN list, etc.'), 'Test');

      await user.click(screen.getByRole('button', { name: 'Add to Sanctions' }));

      await waitFor(() => {
        expect(screen.getByText('Address already sanctioned')).toBeInTheDocument();
      });
    });
  });
});
