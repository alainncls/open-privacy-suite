import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';

vi.mock('../CurrencyContext', async () => {
  const actual = await vi.importActual('../CurrencyContext');
  return actual;
});

import CurrencySelector from '../CurrencySelector';

describe('CurrencySelector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading state while currency loads', async () => {
      server.use(
        http.get('/api/v1/admin/compliance/currency', async () => {
          await delay('infinite');
          return HttpResponse.json({
            currency: 'usd',
            all_currencies: [{ code: 'usd', name: 'US Dollar', symbol: '$' }],
          });
        })
      );

      const { unmount } = renderWithComplianceContext(<CurrencySelector />);

      expect(screen.getByText('Currency...')).toBeInTheDocument();
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();

      unmount();
    });

    it('shows current currency after loading', async () => {
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByText('$ USD')).toBeInTheDocument();
      });

      expect(screen.getByText('Currency:')).toBeInTheDocument();
    });

    it('displays selector with correct test id', async () => {
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByTestId('currency-selector')).toBeInTheDocument();
      });
    });
  });

  describe('Interactions', () => {
    it('calls API when currency is changed', async () => {
      let putCalled = false;
      let putBody: { currency: string } | null = null;

      server.use(
        http.put('/api/v1/admin/compliance/currency', async ({ request }) => {
          putCalled = true;
          putBody = await request.json() as { currency: string };
          return HttpResponse.json({
            currency: putBody.currency,
            all_currencies: [
              { code: 'usd', name: 'US Dollar', symbol: '$' },
              { code: 'eur', name: 'Euro', symbol: '\u20ac' },
              { code: 'chf', name: 'Swiss Franc', symbol: 'CHF' },
              { code: 'gbp', name: 'British Pound', symbol: '\u00a3' },
              { code: 'aed', name: 'UAE Dirham', symbol: 'AED' },
            ],
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<CurrencySelector />);

      // Wait for selector to load
      await waitFor(() => {
        expect(screen.getByText('$ USD')).toBeInTheDocument();
      });

      // Open the dropdown
      await user.click(screen.getByTestId('currency-selector'));

      // Wait for dropdown content to appear and select EUR
      await waitFor(() => {
        expect(screen.getByText('EUR')).toBeInTheDocument();
      });

      await user.click(screen.getByText('EUR'));

      // Verify the API was called
      await waitFor(() => {
        expect(putCalled).toBe(true);
      });

      expect(putBody?.currency).toBe('eur');
    });

    it('shows all available currencies in dropdown', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByTestId('currency-selector')).toBeInTheDocument();
      });

      // Open dropdown
      await user.click(screen.getByTestId('currency-selector'));

      await waitFor(() => {
        expect(screen.getByText('(US Dollar)')).toBeInTheDocument();
        expect(screen.getByText('(Euro)')).toBeInTheDocument();
        expect(screen.getByText('(Swiss Franc)')).toBeInTheDocument();
        expect(screen.getByText('(British Pound)')).toBeInTheDocument();
        expect(screen.getByText('(UAE Dirham)')).toBeInTheDocument();
      });
    });
  });
});
