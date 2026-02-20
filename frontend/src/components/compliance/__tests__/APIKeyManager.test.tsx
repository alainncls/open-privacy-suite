import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import type { APIKey, PriceChangeLog } from '@/types/compliance';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import APIKeyManager from '../APIKeyManager';

const mockAPIKeys: APIKey[] = [
  {
    id: 'key-1',
    name: 'Production Key',
    key_prefix: 'ppk_pro',
    permissions: [],
    last_used_at: '2024-01-15T00:00:00Z',
    created_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'key-2',
    name: 'Expired Key',
    key_prefix: 'ppk_exp',
    permissions: [],
    expires_at: '2024-01-01T00:00:00Z',
    created_at: '2023-01-01T00:00:00Z',
  },
  {
    id: 'key-3',
    name: 'Revoked Key',
    key_prefix: 'ppk_rev',
    permissions: [],
    revoked_at: '2024-01-10T00:00:00Z',
    created_at: '2023-06-01T00:00:00Z',
  },
];

const mockPriceChanges: PriceChangeLog[] = [
  {
    id: 1,
    api_key_id: 'key-1',
    api_key_name: 'Production Key',
    token_address: '0x1111111111111111111111111111111111111111',
    symbol: 'TESTTOKEN',
    old_price: 100,
    new_price: 150,
    deviation_pct: 50,
    ip_address: '192.168.1.1',
    ip_changed: false,
    created_at: '2024-01-15T10:30:00Z',
  },
  {
    id: 2,
    api_key_id: 'key-1',
    api_key_name: 'Production Key',
    token_address: '0x2222222222222222222222222222222222222222',
    symbol: 'NEWTOKEN',
    new_price: 50,
    ip_address: '10.0.0.1',
    ip_changed: true,
    created_at: '2024-01-15T11:00:00Z',
  },
];

function setupDefaultHandlers() {
  server.use(
    http.get('/api/v1/admin/compliance/api-keys', () => {
      return HttpResponse.json({ data: mockAPIKeys });
    }),
    http.get('/api/v1/admin/compliance/external-rates-settings', () => {
      return HttpResponse.json({
        max_price_deviation_pct: 50,
        price_update_cooldown_minutes: 1440,
      });
    }),
    http.get('/api/v1/admin/compliance/price-change-log', () => {
      return HttpResponse.json({
        data: mockPriceChanges,
        total: 2,
        limit: 25,
        offset: 0,
      });
    }),
  );
}

describe('APIKeyManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupDefaultHandlers();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/compliance/api-keys', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [] });
        }),
      );

      const { unmount } = renderWithComplianceContext(<APIKeyManager />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no API keys', async () => {
      server.use(
        http.get('/api/v1/admin/compliance/api-keys', () => {
          return HttpResponse.json({ data: [] });
        }),
      );

      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('No API keys')).toBeInTheDocument();
      });
    });

    it('displays API keys table with data', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        // "Production Key" appears in both API keys table and price change log
        expect(screen.getAllByText('Production Key').length).toBeGreaterThanOrEqual(1);
        expect(screen.getByText('Expired Key')).toBeInTheDocument();
        expect(screen.getByText('Revoked Key')).toBeInTheDocument();
      });

      // Key prefix renders as text content containing the prefix
      expect(screen.getByText(/ppk_pro/)).toBeInTheDocument();
      expect(screen.getByText(/ppk_exp/)).toBeInTheDocument();
      expect(screen.getByText(/ppk_rev/)).toBeInTheDocument();
    });

    it('shows correct status badges', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('active')).toBeInTheDocument();
        expect(screen.getByText('expired')).toBeInTheDocument();
        expect(screen.getByText('revoked')).toBeInTheDocument();
      });
    });

    it('shows revoke button only for active keys', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getAllByText('Production Key').length).toBeGreaterThanOrEqual(1);
      });

      // Only 1 active key, so only 1 trash icon button in the keys table
      const trashButtons = document.querySelectorAll('.lucide-trash2');
      expect(trashButtons).toHaveLength(1);
    });
  });

  describe('API Key CRUD', () => {
    it('opens create dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('Create API Key')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create API Key'));

      await waitFor(() => {
        expect(screen.getByPlaceholderText('e.g., Production backend')).toBeInTheDocument();
        expect(screen.getByText('Expires in (days)')).toBeInTheDocument();
      });
    });

    it('validates empty name in create form', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('Create API Key')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create API Key'));

      await waitFor(() => {
        expect(screen.getByPlaceholderText('e.g., Production backend')).toBeInTheDocument();
      });

      // Type a space only so the required attribute is satisfied but our trim check catches it
      const nameInput = screen.getByPlaceholderText('e.g., Production backend');
      await user.type(nameInput, ' ');

      // Submit form by clicking Create button inside dialog
      const createButtons = screen.getAllByRole('button', { name: 'Create' });
      const submitButton = createButtons[createButtons.length - 1];
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Name is required')).toBeInTheDocument();
      });
    });

    it('creates API key and shows key display dialog', async () => {
      server.use(
        http.post('/api/v1/admin/compliance/api-keys', () => {
          return HttpResponse.json({
            key: 'ppk_test_full_secret_key_value',
            id: 'key-new',
            name: 'My New Key',
            key_prefix: 'ppk_tes',
            permissions: [],
            created_at: '2024-01-20T00:00:00Z',
          });
        }),
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('Create API Key')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create API Key'));

      await waitFor(() => {
        expect(screen.getByPlaceholderText('e.g., Production backend')).toBeInTheDocument();
      });

      await user.type(screen.getByPlaceholderText('e.g., Production backend'), 'My New Key');

      const createButtons = screen.getAllByRole('button', { name: 'Create' });
      const submitButton = createButtons[createButtons.length - 1];
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('API Key Created')).toBeInTheDocument();
        expect(screen.getByText('ppk_test_full_secret_key_value')).toBeInTheDocument();
        expect(screen.getByText(/Copy this key now/)).toBeInTheDocument();
      });
    });

    it('revokes API key after confirmation', async () => {
      let revokeCalled = false;
      server.use(
        http.delete('/api/v1/admin/compliance/api-keys/:id', () => {
          revokeCalled = true;
          return HttpResponse.json({ message: 'revoked' });
        }),
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getAllByText('Production Key').length).toBeGreaterThanOrEqual(1);
      });

      // Click the trash icon button (only one for the active key)
      const trashButton = document.querySelector('.lucide-trash2')?.closest('button');
      expect(trashButton).toBeTruthy();
      await user.click(trashButton!);

      await waitFor(() => {
        expect(screen.getByText('Revoke API Key')).toBeInTheDocument();
        expect(screen.getByText(/Are you sure you want to revoke/)).toBeInTheDocument();
      });

      await user.click(screen.getByRole('button', { name: 'Revoke' }));

      await waitFor(() => {
        expect(revokeCalled).toBe(true);
      });
    });
  });

  describe('External Rates Security Settings', () => {
    it('displays settings with loaded values', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('External Rates Security')).toBeInTheDocument();
      });

      await waitFor(() => {
        expect(screen.getByDisplayValue('50')).toBeInTheDocument();
        expect(screen.getByDisplayValue('1440')).toBeInTheDocument();
      });
    });

    it('saves settings successfully', async () => {
      let putCalled = false;
      server.use(
        http.put('/api/v1/admin/compliance/external-rates-settings', async ({ request }) => {
          putCalled = true;
          const body = await request.json() as Record<string, unknown>;
          return HttpResponse.json(body);
        }),
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('50')).toBeInTheDocument();
      });

      const deviationInput = screen.getByDisplayValue('50');
      await user.clear(deviationInput);
      await user.type(deviationInput, '75');

      await user.click(screen.getByRole('button', { name: 'Save Settings' }));

      await waitFor(() => {
        expect(putCalled).toBe(true);
        expect(screen.getByText('Saved')).toBeInTheDocument();
      });
    });

    it('shows error when settings save fails', async () => {
      server.use(
        http.put('/api/v1/admin/compliance/external-rates-settings', () => {
          return HttpResponse.json({ error: 'Failed to save settings' }, { status: 500 });
        }),
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('50')).toBeInTheDocument();
      });

      await user.click(screen.getByRole('button', { name: 'Save Settings' }));

      await waitFor(() => {
        expect(screen.getByText('Failed to save settings')).toBeInTheDocument();
      });
    });
  });

  describe('Price Change Audit Log', () => {
    it('shows empty state when no price changes', async () => {
      server.use(
        http.get('/api/v1/admin/compliance/price-change-log', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        }),
      );

      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('No price changes recorded')).toBeInTheDocument();
      });
    });

    it('displays price change log table', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('Price Change Audit Log')).toBeInTheDocument();
      });

      await waitFor(() => {
        expect(screen.getByText('TESTTOKEN')).toBeInTheDocument();
        expect(screen.getByText('NEWTOKEN')).toBeInTheDocument();
        expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
        expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('API Key')).toBeInTheDocument();
      expect(screen.getByText('Token')).toBeInTheDocument();
      expect(screen.getByText('Deviation')).toBeInTheDocument();
      expect(screen.getByText('IP')).toBeInTheDocument();
      expect(screen.getByText('IP Changed')).toBeInTheDocument();
    });

    it('shows IP changed warning icon', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('NEWTOKEN')).toBeInTheDocument();
      });

      // The entry with ip_changed=true should have a warning triangle icon
      const warningIcons = document.querySelectorAll('.lucide-alert-triangle');
      expect(warningIcons.length).toBeGreaterThanOrEqual(1);
    });

    it('shows N/A for new token entries', async () => {
      renderWithComplianceContext(<APIKeyManager />);

      await waitFor(() => {
        expect(screen.getByText('NEWTOKEN')).toBeInTheDocument();
      });

      // The NEWTOKEN entry has no old_price, so it should show "N/A"
      const naCells = screen.getAllByText(/N\/A/);
      expect(naCells.length).toBeGreaterThanOrEqual(1);
    });
  });
});
