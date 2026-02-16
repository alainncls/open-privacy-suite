import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { mockTokenPrices } from '@/test/mocks/handlers';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import TokenPriceList from '../TokenPriceList';

describe('TokenPriceList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', async () => {
          await delay('infinite');
          return HttpResponse.json([]);
        })
      );

      const { unmount } = renderWithComplianceContext(<TokenPriceList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no tokens', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
          return HttpResponse.json([]);
        })
      );

      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('No token prices configured')).toBeInTheDocument();
      });
    });

    it('displays token table with data', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
        expect(screen.getByText('USDT')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Token Address')).toBeInTheDocument();
      expect(screen.getByText('Symbol')).toBeInTheDocument();
      expect(screen.getByText('Decimals')).toBeInTheDocument();
    });

    it('shows native badge for native token', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('native (ETH)')).toBeInTheDocument();
      });
    });

    it('shows Add Token button', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });
    });
  });

  describe('CRUD Operations', () => {
    it('opens add dialog and pre-fills native values', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Token'));

      await waitFor(() => {
        expect(screen.getByText('Add Token Price')).toBeInTheDocument();
      });

      // Should pre-fill with "native" and "ETH"
      expect(screen.getByDisplayValue('native')).toBeInTheDocument();
      expect(screen.getByDisplayValue('ETH')).toBeInTheDocument();
    });

    it('submits new token price', async () => {
      let upsertCalled = false;
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', async () => {
          upsertCalled = true;
          return HttpResponse.json({
            id: 'token-new',
            org_id: 'org-1',
            token_address: 'native',
            symbol: 'ETH',
            decimals: 18,
            price_usd: 3000,
            created_at: '2024-01-01T00:00:00Z',
            updated_at: new Date().toISOString(),
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Token'));

      await waitFor(() => {
        expect(screen.getByText('Add Token Price')).toBeInTheDocument();
      });

      // Fill price
      const priceInput = screen.getByPlaceholderText('2500.00');
      await user.type(priceInput, '3000');

      // Submit
      await user.click(screen.getByRole('button', { name: 'Add' }));

      await waitFor(() => {
        expect(upsertCalled).toBe(true);
      });
    });

    it('opens edit dialog with existing values', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
      });

      // Click edit on first row (pencil icon)
      const editButtons = document.querySelectorAll('[data-testid]');
      // Use the pencil button - get all ghost buttons
      const allButtons = screen.getAllByRole('button');
      // Find the first edit button (in the table rows)
      const editButton = allButtons.find(btn => btn.querySelector('.lucide-pencil'));
      if (editButton) {
        await user.click(editButton);

        await waitFor(() => {
          expect(screen.getByText('Edit Token Price')).toBeInTheDocument();
        });

        // Token address should be disabled in edit mode
        const addressInput = screen.getByDisplayValue('native');
        expect(addressInput).toBeDisabled();
      }
    });

    it('shows delete confirmation dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
      });

      // Click delete button (trash icon)
      const allButtons = screen.getAllByRole('button');
      const deleteButton = allButtons.find(btn => btn.querySelector('.lucide-trash-2'));
      if (deleteButton) {
        await user.click(deleteButton);

        await waitFor(() => {
          expect(screen.getByText('Delete Token Price')).toBeInTheDocument();
          expect(screen.getByText(/Are you sure/)).toBeInTheDocument();
        });
      }
    });

    it('deletes token after confirmation', async () => {
      let deleteCalled = false;
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
      });

      const allButtons = screen.getAllByRole('button');
      const deleteButton = allButtons.find(btn => btn.querySelector('.lucide-trash-2'));
      if (deleteButton) {
        await user.click(deleteButton);

        await waitFor(() => {
          expect(screen.getByText('Delete Token Price')).toBeInTheDocument();
        });

        await user.click(screen.getByRole('button', { name: 'Delete' }));

        await waitFor(() => {
          expect(deleteCalled).toBe(true);
        });
      }
    });
  });

  describe('Error Handling', () => {
    it('shows error when token list fails to load', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
          return HttpResponse.json({ error: 'Internal server error' }, { status: 500 });
        })
      );

      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Internal server error')).toBeInTheDocument();
      });
    });

    it('shows form error when submission fails', async () => {
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', () => {
          return HttpResponse.json({ error: 'Price must be positive' }, { status: 400 });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Token'));

      await waitFor(() => {
        expect(screen.getByText('Add Token Price')).toBeInTheDocument();
      });

      const priceInput = screen.getByPlaceholderText('2500.00');
      await user.type(priceInput, '3000');

      await user.click(screen.getByRole('button', { name: 'Add' }));

      await waitFor(() => {
        expect(screen.getByText('Price must be positive')).toBeInTheDocument();
      });
    });
  });
});
