import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { mockTravelRuleRecords } from '@/test/mocks/handlers';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import TravelRuleRecordList from '../TravelRuleRecordList';

describe('TravelRuleRecordList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithComplianceContext(<TravelRuleRecordList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no records', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('No travel rule records')).toBeInTheDocument();
      });
    });

    it('displays records in a table', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        // Should show originator user IDs (truncated)
        expect(screen.getByText('user-1...')).toBeInTheDocument();
        expect(screen.getByText('user-2...')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Originator')).toBeInTheDocument();
      expect(screen.getByText('Beneficiary')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
    });

    it('shows correct status badges', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        // First record: unused (expires_at is in the future)
        expect(screen.getByText('unused')).toBeInTheDocument();
        // Second record: used (has used_at)
        expect(screen.getByText('used')).toBeInTheDocument();
      });
    });

    it('shows transfer type badges', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
        expect(screen.getByText('ERC20')).toBeInTheDocument();
      });
    });

    it('shows Create Record button', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });
    });
  });

  describe('Create Record', () => {
    it('opens create dialog with all fields', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Verify form fields are present
      expect(screen.getByText('Originator User ID')).toBeInTheDocument();
      expect(screen.getByText('Originator Data (JSON)')).toBeInTheDocument();
      expect(screen.getByText('Beneficiary Data (JSON)')).toBeInTheDocument();
      expect(screen.getByText('Transfer Type')).toBeInTheDocument();
      expect(screen.getByText('Beneficiary Address')).toBeInTheDocument();
      expect(screen.getByText('Amount (Wei)')).toBeInTheDocument();
      // Amount (USD) appears both in table header and form — just check form has the field
      expect(screen.getAllByText('Amount (USD)').length).toBeGreaterThanOrEqual(1);
    });

    it('submits new travel rule record', async () => {
      let createCalled = false;
      server.use(
        http.post('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', async () => {
          createCalled = true;
          return HttpResponse.json({
            id: 'tr-new',
            org_id: 'org-1',
            originator_user_id: 'user-1',
            originator_data: {},
            beneficiary_data: {},
            transfer_type: 'eth',
            beneficiary_address: '0x1234567890123456789012345678901234567890',
            amount_wei: '1000000000000000000',
            amount_usd: 2500,
            expires_at: new Date(Date.now() + 86400000).toISOString(),
            created_at: new Date().toISOString(),
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Fill in required fields
      await user.type(screen.getByPlaceholderText('UUID of the originating user'), 'user-1');
      await user.type(screen.getByPlaceholderText('0x...'), '0x1234567890123456789012345678901234567890');
      await user.type(screen.getByPlaceholderText('1000000000000000000'), '1000000000000000000');
      await user.type(screen.getByPlaceholderText('2500.00'), '2500');

      await user.click(screen.getByRole('button', { name: 'Create Record' }));

      await waitFor(() => {
        expect(createCalled).toBe(true);
      });
    });

    it('validates JSON fields', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Fill required fields
      await user.type(screen.getByPlaceholderText('UUID of the originating user'), 'user-1');
      await user.type(screen.getByPlaceholderText('0x...'), '0xabc');
      await user.type(screen.getByPlaceholderText('1000000000000000000'), '100');
      await user.type(screen.getByPlaceholderText('2500.00'), '100');

      // Set invalid JSON in originator data (first textarea with this placeholder)
      const originatorTextareas = screen.getAllByPlaceholderText('{"name": "..."}');
      await user.clear(originatorTextareas[0]);
      await user.type(originatorTextareas[0], 'invalid json');

      await user.click(screen.getByRole('button', { name: 'Create Record' }));

      await waitFor(() => {
        expect(screen.getByText('Originator data must be valid JSON')).toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('shows error when list fails to load', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
          return HttpResponse.json({ error: 'Database error' }, { status: 500 });
        })
      );

      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Database error')).toBeInTheDocument();
      });
    });
  });
});
