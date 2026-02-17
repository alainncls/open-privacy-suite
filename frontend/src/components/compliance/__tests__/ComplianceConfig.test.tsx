import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { mockComplianceConfig } from '@/test/mocks/handlers';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import ComplianceConfig from '../ComplianceConfig';

describe('ComplianceConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/config', async () => {
          await delay('infinite');
          return HttpResponse.json(mockComplianceConfig);
        })
      );

      const { unmount } = renderWithComplianceContext(<ComplianceConfig />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows config form after loading', async () => {
      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText('Compliance Configuration')).toBeInTheDocument();
      });

      expect(screen.getByText('Enforcement')).toBeInTheDocument();
      expect(screen.getByText('Threshold (USD)')).toBeInTheDocument();
      expect(screen.getByText('Save Configuration')).toBeInTheDocument();
    });

    it('shows Enabled badge when config is enabled', async () => {
      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText('Enabled')).toBeInTheDocument();
      });
    });

    it('shows Disabled badge when config is disabled', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/config', () => {
          return HttpResponse.json({ ...mockComplianceConfig, enabled: false });
        })
      );

      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        // The badge says "Disabled"
        const badges = screen.getAllByText('Disabled');
        expect(badges.length).toBeGreaterThan(0);
      });
    });

    it('populates threshold from API response', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/config', () => {
          return HttpResponse.json({ ...mockComplianceConfig, threshold_usd: 5000 });
        })
      );

      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        const input = screen.getByDisplayValue('5000');
        expect(input).toBeInTheDocument();
      });
    });

    it('shows default values when no config exists (404)', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/config', () => {
          return HttpResponse.json({ error: 'not found' }, { status: 404 });
        })
      );

      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText('No configuration saved yet. Save to create the initial config.')).toBeInTheDocument();
      });
    });
  });

  describe('Interactions', () => {
    it('saves config and shows success message', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText('Save Configuration')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save Configuration'));

      await waitFor(() => {
        expect(screen.getByText('Configuration saved successfully')).toBeInTheDocument();
      });
    });

    it('toggles enabled state when clicking enforcement button', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText('Compliance Configuration')).toBeInTheDocument();
      });

      // Initially enabled — button says "Click to disable"
      const toggleButton = screen.getByText(/Click to disable/);
      await user.click(toggleButton);

      // Now it should say "Click to enable"
      expect(screen.getByText(/Click to enable/)).toBeInTheDocument();
    });

    it('shows error when save fails', async () => {
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/config', () => {
          return HttpResponse.json({ error: 'Invalid threshold' }, { status: 400 });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText('Save Configuration')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save Configuration'));

      await waitFor(() => {
        expect(screen.getByText('Invalid threshold')).toBeInTheDocument();
      });
    });

    it('shows last updated timestamp', async () => {
      renderWithComplianceContext(<ComplianceConfig />);

      await waitFor(() => {
        expect(screen.getByText(/Last updated:/)).toBeInTheDocument();
      });
    });
  });
});
