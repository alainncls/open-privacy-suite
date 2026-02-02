import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import GroupList from '../GroupList';
import {
  mockGroupHierarchy,
  mockGroupAccessFull,
  mockGroupAccessReadOnly,
} from '@/test/mocks/rbac-fixtures';
import { mockGroup, mockGroupAccess, mockOrganization } from '@/test/mocks/handlers';

// Mock the useOrgContext hook from RBACManager
// Note: vi.mock is hoisted, so create context inside the factory
vi.mock('../RBACManager', async () => {
  const { createContext } = await import('react');
  const { mockOrganization } = await import('@/test/mocks/handlers');
  const MockOrgContext = createContext(null);
  // Return a static context since GroupList.test.tsx doesn't use renderWithRBACContext
  return {
    OrgContext: MockOrgContext,
    useOrgContext: () => ({
      selectedOrg: mockOrganization,
      setSelectedOrg: vi.fn(),
      organizations: [mockOrganization],
      refreshOrgs: vi.fn(),
    }),
  };
});

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

// Helper to render GroupList with necessary providers
function renderGroupList() {
  const queryClient = createTestQueryClient();

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter>
          <GroupList />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe('GroupList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', () => {
      // Use a handler that delays response
      server.use(
        http.get('/api/v1/orgs/:orgId/groups', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json([mockGroup]);
        })
      );

      renderGroupList();

      // The component shows loading state
      expect(document.querySelector('.animate-spin')).toBeInTheDocument();
    });

    it('shows "Groups" heading', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Groups')).toBeInTheDocument();
      });
    });

    it('shows empty state when no groups', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups', () => {
          return HttpResponse.json([]);
        })
      );

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('No groups found')).toBeInTheDocument();
      });

      expect(screen.getByText('Create your first group')).toBeInTheDocument();
    });

    it('displays groups after loading', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });
    });
  });

  describe('Hierarchy Display', () => {
    beforeEach(() => {
      // Setup hierarchical groups
      server.use(
        http.get('/api/v1/orgs/:orgId/groups', () => {
          return HttpResponse.json(mockGroupHierarchy);
        }),
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', ({ params }) => {
          if (params.groupId === 'group-engineering') {
            return HttpResponse.json(mockGroupAccessFull);
          }
          if (params.groupId === 'group-operations') {
            return HttpResponse.json(mockGroupAccessReadOnly);
          }
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('shows group path reflecting hierarchy', async () => {
      renderGroupList();

      await waitFor(() => {
        // Check for the root group name
        expect(screen.getByText('Root')).toBeInTheDocument();
      });

      // Check for nested paths - these are unique
      await waitFor(() => {
        expect(screen.getByText('root.engineering')).toBeInTheDocument();
      });
    });

    it('shows depth level correctly for nested groups', async () => {
      renderGroupList();

      await waitFor(() => {
        // Root has depth 0, Engineering has depth 1
        expect(screen.getByText('Root')).toBeInTheDocument();
        expect(screen.getByText('Engineering')).toBeInTheDocument();
      });

      // DevOps has depth 2 and path root.engineering.devops
      await waitFor(() => {
        expect(screen.getByText('DevOps')).toBeInTheDocument();
        expect(screen.getByText('root.engineering.devops')).toBeInTheDocument();
      });
    });

    it('root groups have depth 0', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root')).toBeInTheDocument();
        // The Root group should have path 'root' (no dots = depth 0)
        // 'root' appears multiple times (slug badge and path), so just verify root group exists
        const rootElements = screen.getAllByText('root');
        expect(rootElements.length).toBeGreaterThan(0);
      });
    });

    it('child groups show parent path', async () => {
      renderGroupList();

      await waitFor(() => {
        // Engineering is child of Root
        expect(screen.getByText('root.engineering')).toBeInTheDocument();
        // DevOps is child of Engineering
        expect(screen.getByText('root.engineering.devops')).toBeInTheDocument();
        // Frontend is also child of Engineering
        expect(screen.getByText('root.engineering.frontend')).toBeInTheDocument();
      });
    });
  });

  describe('Actions', () => {
    it('Create button opens GroupForm dialog', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Add Group')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Group'));

      await waitFor(() => {
        // The dialog title is "Create Group", check for the dialog heading
        expect(screen.getByRole('heading', { name: 'Create Group' })).toBeInTheDocument();
      });
    });

    it('Edit button opens form with group data', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the edit button (Pencil icon)
      const editButton = screen.getByTitle('Edit group');
      await user.click(editButton);

      await waitFor(() => {
        expect(screen.getByText('Edit Group')).toBeInTheDocument();
      });

      // The form should be populated with group data
      expect(screen.getByDisplayValue('Root Group')).toBeInTheDocument();
    });

    it('Access button opens GroupAccessForm', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the settings button (Settings icon for access)
      const accessButton = screen.getByTitle('Edit access settings');
      await user.click(accessButton);

      await waitFor(() => {
        expect(screen.getByText(/Edit Access for/)).toBeInTheDocument();
      });
    });

    it('Delete shows confirmation', async () => {
      const user = userEvent.setup();

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the delete button
      const deleteButton = screen.getByTitle('Delete group');
      await user.click(deleteButton);

      // Confirmation dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      expect(screen.getByText(/Are you sure you want to delete/)).toBeInTheDocument();
    });

    it('Cannot delete group with children - shows error dialog', async () => {
      const user = userEvent.setup();

      // Setup handler that returns error for delete
      server.use(
        http.delete('/api/v1/orgs/:orgId/groups/:groupId', () => {
          return HttpResponse.json(
            { error: 'Cannot delete group with children' },
            { status: 400 }
          );
        })
      );

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete group');
      await user.click(deleteButton);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Error dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText(/Failed to delete group/)).toBeInTheDocument();
    });

    it('Add child button opens form with parent preset', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the add child button (Plus icon)
      const addChildButton = screen.getByTitle('Add child group');
      await user.click(addChildButton);

      await waitFor(() => {
        expect(screen.getByText(/Add child group to "Root Group"/)).toBeInTheDocument();
      });
    });
  });

  describe('Org Admin Badge', () => {
    it('shows Org Admin badge for admin groups', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups', () => {
          return HttpResponse.json(mockGroupHierarchy);
        }),
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupList();

      await waitFor(() => {
        // The Root group in mockGroupHierarchy has is_org_admin: true
        expect(screen.getByText('Org Admin')).toBeInTheDocument();
      });
    });
  });

  describe('Methods Count Display', () => {
    it('shows methods count when group has allowed methods', async () => {
      server.use(
        http.get('/api/v1/orgs/:orgId/groups', () => {
          return HttpResponse.json([mockGroup]);
        }),
        http.get('/api/v1/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            allowed_methods: ['eth_call', 'eth_getBalance', 'eth_sendTransaction'],
          });
        })
      );

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('3 methods')).toBeInTheDocument();
      });
    });
  });
});
