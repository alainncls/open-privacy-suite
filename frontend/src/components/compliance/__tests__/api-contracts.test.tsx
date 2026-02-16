/**
 * Backend Response Contract Tests
 *
 * These tests verify that the frontend compliance components correctly handle
 * the EXACT response shapes returned by the real backend (admin_compliance.go).
 *
 * Purpose: Catch frontend/backend contract mismatches that regular MSW-mocked
 * tests miss because the mocks might not match the real backend shapes.
 *
 * Real backend response shapes:
 *   GET  /config              -> ComplianceConfig directly (no wrapper)
 *   PUT  /config              -> ComplianceConfig directly (no wrapper)
 *   GET  /tokens              -> {data: TokenPrice[]} (wrapped, NOT paginated)
 *   PUT  /tokens/:addr        -> TokenPrice directly (no wrapper)
 *   DELETE /tokens/:addr      -> {message: "token price deleted"}
 *   GET  /travel-rule-records -> {data: TravelRuleRecord[], total, limit, offset} (paginated)
 *   POST /travel-rule-records -> TravelRuleRecord directly with 201
 *   GET  /sanctions           -> {data: SanctionedAddress[], total, limit, offset} (paginated)
 *   POST /sanctions           -> SanctionedAddress directly with 201
 *   DELETE /sanctions/:id     -> {message: "sanctioned address removed"}
 *   GET  /logs                -> {data: ComplianceLog[], total, limit, offset} (paginated)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';

// vi.mock is hoisted, so this single mock covers all 5 component imports below
vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

// Import all components AFTER the vi.mock
import TokenPriceList from '../TokenPriceList';
import ComplianceConfig from '../ComplianceConfig';
import TravelRuleRecordList from '../TravelRuleRecordList';
import SanctionsList from '../SanctionsList';
import ComplianceLogList from '../ComplianceLogList';

// ---------------------------------------------------------------------------
// Realistic mock data matching the exact shapes the Go backend returns
// ---------------------------------------------------------------------------

const realisticTokenPrices = [
  {
    id: 'tp-1', org_id: 'org-1', token_address: 'native',
    symbol: 'ETH', decimals: 18, price_usd: 2500,
    created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-15T00:00:00Z',
  },
];

const realisticConfig = {
  id: 'cfg-1', org_id: 'org-1', enabled: true, threshold_usd: 3000,
  created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-15T00:00:00Z',
};

const realisticTravelRuleRecords = [
  {
    id: 'tr-1', org_id: 'org-1', originator_user_id: 'user-abc-123',
    originator_data: { name: 'Alice' }, beneficiary_data: { name: 'Bob' },
    transfer_type: 'eth', beneficiary_address: '0xabcdef1234567890abcdef1234567890abcdef12',
    amount_wei: '1000000000000000000', amount_usd: 2500,
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    created_at: '2024-01-15T00:00:00Z',
  },
];

const realisticSanctions = [
  {
    id: 'sanc-1', address: '0x1234567890abcdef1234567890abcdef12345678',
    reason: 'OFAC SDN list', source: 'OFAC', org_id: null,
    created_at: '2024-01-10T00:00:00Z', updated_at: '2024-01-10T00:00:00Z',
  },
];

const realisticLogs = [
  {
    id: 1, org_id: 'org-1', user_id: 'user-abc-12345678',
    transfer_type: 'eth', from_address: '0xaaaa00000000000000000000000000000000aaaa',
    to_address: '0xbbbb00000000000000000000000000000000bbbb',
    amount_wei: '5000000000000000000', amount_usd: 12500,
    threshold_usd: 3000, decision: 'allowed', created_at: '2024-01-15T10:00:00Z',
  },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Backend Response Contract Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('token prices list parses wrapped {data: [...]} response', async () => {
    // Backend returns {data: TokenPrice[]} — NOT a raw array, NOT paginated
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
        return HttpResponse.json({ data: realisticTokenPrices });
      }),
    );

    renderWithComplianceContext(<TokenPriceList />);

    await waitFor(() => {
      expect(screen.getByText('ETH')).toBeInTheDocument();
    });

    // Verify the token address is displayed (rendered as "native (ETH)")
    expect(screen.getByText('native (ETH)')).toBeInTheDocument();
  });

  it('compliance config parses unwrapped response', async () => {
    // Backend returns ComplianceConfig directly — no wrapper object
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/config', () => {
        return HttpResponse.json(realisticConfig);
      }),
    );

    renderWithComplianceContext(<ComplianceConfig />);

    await waitFor(() => {
      expect(screen.getByText('Compliance Configuration')).toBeInTheDocument();
    });

    // Verify the enabled badge renders
    expect(screen.getByText('Enabled')).toBeInTheDocument();

    // Verify the threshold value is populated in the input
    expect(screen.getByDisplayValue('3000')).toBeInTheDocument();

    // Verify the last updated timestamp is shown
    expect(screen.getByText(/Last updated:/)).toBeInTheDocument();
  });

  it('travel rule records list parses paginated response', async () => {
    // Backend returns {data: TravelRuleRecord[], total, limit, offset}
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
        return HttpResponse.json({
          data: realisticTravelRuleRecords,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<TravelRuleRecordList />);

    await waitFor(() => {
      expect(screen.getByText('Travel Rule Records')).toBeInTheDocument();
    });

    // Verify record data renders: originator user ID is sliced to first 8 chars
    expect(screen.getByText('user-abc...')).toBeInTheDocument();

    // Verify the amount USD is displayed
    expect(screen.getByText('$2,500')).toBeInTheDocument();

    // Verify the transfer type badge
    expect(screen.getByText('ETH')).toBeInTheDocument();

    // Verify status badge (expires_at is in the future, not used -> "unused")
    expect(screen.getByText('unused')).toBeInTheDocument();
  });

  it('sanctions list parses paginated response', async () => {
    // Backend returns {data: SanctionedAddress[], total, limit, offset}
    server.use(
      http.get('/api/v1/admin/compliance/sanctions', () => {
        return HttpResponse.json({
          data: realisticSanctions,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<SanctionsList />);

    await waitFor(() => {
      expect(screen.getByText('Sanctioned Addresses')).toBeInTheDocument();
    });

    // Verify the reason column displays the sanction reason
    expect(screen.getByText('OFAC SDN list')).toBeInTheDocument();

    // Verify the source column
    expect(screen.getByText('OFAC')).toBeInTheDocument();

    // Verify the scope badge (org_id is null -> Global)
    expect(screen.getByText('Global')).toBeInTheDocument();
  });

  it('compliance logs list parses paginated response', async () => {
    // Backend returns {data: ComplianceLog[], total, limit, offset}
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () => {
        return HttpResponse.json({
          data: realisticLogs,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<ComplianceLogList />);

    await waitFor(() => {
      expect(screen.getByText('Compliance Logs')).toBeInTheDocument();
    });

    // Verify the user ID is sliced (first 8 chars + "...")
    expect(screen.getByText('user-abc...')).toBeInTheDocument();

    // Verify transfer type badge
    expect(screen.getByText('ETH')).toBeInTheDocument();

    // Verify amount USD
    expect(screen.getByText('$12,500')).toBeInTheDocument();

    // Verify decision badge
    expect(screen.getByText('allowed')).toBeInTheDocument();
  });
});
