import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import { mockOrganizations, createMockOrganization } from '@/test/mocks/rbac-fixtures';
import type { Organization } from '@/types/rbac';
import React, { useState } from 'react';

// Mock the useOrgContext hook from RBACManager
// Use the shared TestOrgContext from test-utils so MockOrgProvider works
vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
  };
});

// Import after mock is set up
import OrganizationList from '../OrganizationList';
import { TestOrgContext } from './test-utils';

// Note: We no longer mock window.confirm and window.alert since we use styled dialogs

// Create a fresh QueryClient for each test
function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

interface MockOrgProviderProps {
  children: React.ReactNode;
  organizations?: Organization[];
  onOrgChange?: (org: Organization | null) => void;
}

function MockOrgProvider({
  children,
  organizations: initialOrganizations = [],
  onOrgChange,
}: MockOrgProviderProps) {
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>(initialOrganizations);

  const handleSetSelectedOrg = (org: Organization | null) => {
    setSelectedOrg(org);
    onOrgChange?.(org);
  };

  const refreshOrgs = async () => {
    // Fetch from mock API
    const response = await fetch('/api/v1/orgs');
    const json = await response.json();
    // Handle both paginated and plain array formats
    const data = json.data || json;
    setOrganizations(data);
  };

  return (
    <TestOrgContext.Provider
      value={{
        selectedOrg,
        setSelectedOrg: handleSetSelectedOrg,
        organizations,
        refreshOrgs,
      }}
    >
      {children}
    </TestOrgContext.Provider>
  );
}

function renderOrganizationList(options: { organizations?: Organization[] } = {}) {
  const queryClient = createTestQueryClient();
  const user = userEvent.setup();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter>
          <MockOrgProvider organizations={options.organizations}>
            <OrganizationList />
          </MockOrgProvider>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { user };
}

describe('OrganizationList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.resetHandlers();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', () => {
      // Return organizations after a delay to see loading state
      server.use(
        http.get('/api/v1/orgs', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      // Should show loading spinner (via animate-spin class on Loader2)
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
    });

    it('shows "Organizations" heading and description text', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      expect(screen.getByText('Organizations')).toBeInTheDocument();
      expect(
        screen.getByText('Top-level tenants that contain groups and contracts')
      ).toBeInTheDocument();
    });

    it('shows empty state message when no organizations', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('No organizations found')).toBeInTheDocument();
      });

      expect(screen.getByText('Create your first organization')).toBeInTheDocument();
    });

    it('displays table with correct headers (Name, Slug, Created, Actions)', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Name')).toBeInTheDocument();
      });

      expect(screen.getByText('Slug')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Actions')).toBeInTheDocument();
    });
  });

  describe('Data Display', () => {
    it('shows organization name in table row', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('shows organization slug in table row', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('acme-corp')).toBeInTheDocument();
      });
    });

    it('formats created date correctly', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      // mockOrganizations[0].created_at is '2024-01-01T00:00:00Z'
      // Should format as "Jan 1, 2024"
      await waitFor(() => {
        expect(screen.getByText('Jan 1, 2024')).toBeInTheDocument();
      });
    });

    it('shows correct number of rows matching API response', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        // mockOrganizations has 3 organizations
        const table = screen.getByRole('table');
        const rows = within(table).getAllByRole('row');
        // 1 header row + 3 data rows = 4 total
        expect(rows).toHaveLength(4);
      });
    });
  });

  describe('Actions', () => {
    it('Create button opens dialog with OrganizationForm', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      const { user } = renderOrganizationList();

      // Wait for loading to complete and table to show
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      const addButton = screen.getByRole('button', { name: /add organization/i });
      await user.click(addButton);

      // Dialog renders in a portal, use findBy for async content
      await waitFor(() => {
        // Check for dialog title
        expect(screen.getByRole('dialog')).toBeInTheDocument();
      });

      // Form fields should be visible in the dialog
      await waitFor(() => {
        expect(screen.getByPlaceholderText('e.g., Acme Corporation')).toBeInTheDocument();
      });
      expect(screen.getByPlaceholderText('e.g., acme-corp')).toBeInTheDocument();
    });

    it('Edit button opens form populated with org data', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      const { user } = renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      // Find the edit button for the first org (by title attribute)
      const editButtons = screen.getAllByTitle('Edit organization');
      await user.click(editButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Edit Organization')).toBeInTheDocument();
      });

      // Form should be populated with org data
      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      expect(nameInput).toHaveValue('Acme Corporation');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      expect(slugInput).toHaveValue('acme-corp');
    });

    it('Delete button shows confirmation dialog', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      const { user } = renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete organization');
      await user.click(deleteButtons[0]);

      // Verify confirmation dialog appears
      await waitFor(() => {
        expect(screen.getByText('Delete Organization')).toBeInTheDocument();
      });
      expect(screen.getByText(/Are you sure you want to delete "Acme Corporation"/)).toBeInTheDocument();
    });

    it('Delete cancelled does not remove organization', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      const { user } = renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete organization');
      await user.click(deleteButtons[0]);

      // Wait for dialog and click Cancel
      await waitFor(() => {
        expect(screen.getByText('Delete Organization')).toBeInTheDocument();
      });
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      // Organization should still be present
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('Delete success removes organization from list', async () => {
      // Track if delete was called
      let deleteCalled = false;

      server.use(
        http.get('/api/v1/orgs', () => {
          if (deleteCalled) {
            // Return list without the deleted org
            const remaining = mockOrganizations.slice(1);
            return HttpResponse.json({ data: remaining, total: remaining.length, limit: 25, offset: 0 });
          }
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        }),
        http.delete('/api/v1/orgs/:orgId', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const { user } = renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete organization');
      await user.click(deleteButtons[0]);

      // Wait for dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Organization')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      await waitFor(() => {
        expect(screen.queryByText('Acme Corporation')).not.toBeInTheDocument();
      });
    });

    it('Delete failure shows error dialog', async () => {
      server.use(
        http.get('/api/v1/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        }),
        http.delete('/api/v1/orgs/:orgId', () => {
          return HttpResponse.json(
            { error: 'Organization has dependencies' },
            { status: 400 }
          );
        })
      );

      const { user } = renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete organization');
      await user.click(deleteButtons[0]);

      // Wait for confirm dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Organization')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Error dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText(/Failed to delete organization/)).toBeInTheDocument();
    });
  });
});
