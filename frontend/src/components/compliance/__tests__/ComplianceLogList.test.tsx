import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { mockComplianceLogs } from '@/test/mocks/handlers';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import ComplianceLogList from '../ComplianceLogList';

describe('ComplianceLogList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/compliance/logs', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithComplianceContext(<ComplianceLogList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no logs', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/compliance/logs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('No compliance logs')).toBeInTheDocument();
      });
    });

    it('displays logs in a table', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        // Should show user IDs (truncated)
        expect(screen.getByText('user-1...')).toBeInTheDocument();
        expect(screen.getByText('user-2...')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Time')).toBeInTheDocument();
      expect(screen.getByText('User')).toBeInTheDocument();
      expect(screen.getByText('Type')).toBeInTheDocument();
      expect(screen.getByText('Decision')).toBeInTheDocument();
    });

    it('shows decision badges with correct variants', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('allowed')).toBeInTheDocument();
        expect(screen.getByText('denied')).toBeInTheDocument();
      });
    });

    it('shows transfer type badges', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
        expect(screen.getByText('ERC20')).toBeInTheDocument();
      });
    });

    it('shows denial reason for denied logs', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('sanctioned_address')).toBeInTheDocument();
      });
    });

    it('shows USD amounts', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('$1,250')).toBeInTheDocument();
        expect(screen.getByText('$2,000')).toBeInTheDocument();
      });
    });
  });

  describe('Filters', () => {
    it('renders filter controls', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('Compliance Logs')).toBeInTheDocument();
      });

      expect(screen.getByPlaceholderText('Filter by user ID...')).toBeInTheDocument();
    });

    it('filters by decision when selecting Denied', async () => {
      let lastParams: URLSearchParams | null = null;
      server.use(
        http.get('/api/v1/orgs/:orgId/compliance/logs', ({ request }) => {
          lastParams = new URL(request.url).searchParams;
          return HttpResponse.json({
            data: mockComplianceLogs.filter(l => {
              const decision = lastParams?.get('decision');
              return !decision || l.decision === decision;
            }),
            total: 1,
            limit: 25,
            offset: 0,
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('user-1...')).toBeInTheDocument();
      });

      // Click the decision filter trigger
      const triggers = screen.getAllByRole('combobox');
      const decisionTrigger = triggers[0]; // First select = decisions
      await user.click(decisionTrigger);

      // Select "Denied"
      await waitFor(() => {
        const deniedOption = screen.getByRole('option', { name: 'Denied' });
        return user.click(deniedOption);
      });

      // Verify the API was called with the filter
      await waitFor(() => {
        expect(lastParams?.get('decision')).toBe('denied');
      });
    });

    it('filters by user ID with debounce', async () => {
      let lastParams: URLSearchParams | null = null;
      server.use(
        http.get('/api/v1/orgs/:orgId/compliance/logs', ({ request }) => {
          lastParams = new URL(request.url).searchParams;
          return HttpResponse.json({
            data: mockComplianceLogs,
            total: mockComplianceLogs.length,
            limit: 25,
            offset: 0,
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('user-1...')).toBeInTheDocument();
      });

      const userIdInput = screen.getByPlaceholderText('Filter by user ID...');
      await user.type(userIdInput, 'user-1');

      // Wait for debounce and API call
      await waitFor(() => {
        expect(lastParams?.get('user_id')).toBe('user-1');
      }, { timeout: 2000 });
    });
  });

  describe('Read-Only', () => {
    it('does not show create or delete buttons', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('user-1...')).toBeInTheDocument();
      });

      // Logs are read-only — no Add/Create/Delete buttons
      expect(screen.queryByText('Add')).not.toBeInTheDocument();
      expect(screen.queryByText('Create')).not.toBeInTheDocument();
      // No trash icons
      expect(document.querySelector('.lucide-trash-2')).not.toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('shows error when logs fail to load', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/compliance/logs', () => {
          return HttpResponse.json({ error: 'Forbidden' }, { status: 403 });
        })
      );

      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('Forbidden')).toBeInTheDocument();
      });
    });
  });
});
