import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockUsers,
  mockUserFull,
  mockUserNoKyc,
  mockUserBanned,
  createMockUser,
} from '@/test/mocks/rbac-fixtures';
import { mockUser } from '@/test/mocks/handlers';

// Mock the useOrgContext hook from RBACManager
// Use the shared TestOrgContext from test-utils so MockOrgProvider works
vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

// Import after mock is set up
import UserList from '../UserList';

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({}),
  };
});

describe('UserList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockNavigate.mockClear();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      // Set up a delayed response to see the loading state
      server.use(
        http.get('/api/v1/admin/users', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      // Should show loading spinner (Loader2 component)
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
    });

    it('shows "Users" heading', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Users')).toBeInTheDocument();
      });
    });

    it('shows empty state when no users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('No users found')).toBeInTheDocument();
      });

      expect(
        screen.getByText('Users are created automatically when they authenticate')
      ).toBeInTheDocument();
    });

    it('displays table with headers (External ID, Groups, KYC, Status, Created, Note, Actions)', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByRole('columnheader', { name: 'External ID' })).toBeInTheDocument();
      });

      expect(screen.getByRole('columnheader', { name: 'Groups' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'KYC' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Status' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Created' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Note' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Actions' })).toBeInTheDocument();
    });
  });

  describe('Groups column + filters (RD-868)', () => {
    it('renders group badges from user.groups', async () => {
      const user = createMockUser({
        id: 'user-with-groups',
        external_id: 'did:test:groupy',
        groups: [
          {
            group_id: 'g-1',
            slug: 'admins',
            name: 'Admins',
            org_id: 'org-1',
            is_org_admin: true,
          },
          {
            group_id: 'g-2',
            slug: 'members',
            name: 'Members',
            org_id: 'org-1',
            is_org_admin: false,
          },
        ],
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [user], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Admins')).toBeInTheDocument();
      });
      expect(screen.getByText('Members')).toBeInTheDocument();
    });

    it('shows em dash for users with no groups', async () => {
      const user = createMockUser({
        id: 'user-orphan',
        external_id: 'did:test:orphan',
        groups: [],
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [user], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // The em dash is rendered in the Groups cell as a placeholder.
        expect(screen.getByText('—')).toBeInTheDocument();
      });
    });

    it('forwards role param to the users-list API when filter set', async () => {
      const seenRoles: (string | null)[] = [];
      server.use(
        http.get('/api/v1/admin/users', ({ request }) => {
          const url = new URL(request.url);
          seenRoles.push(url.searchParams.get('role'));
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(seenRoles.length).toBeGreaterThan(0);
      });
      // First load: no role filter selected -> param absent.
      expect(seenRoles[0]).toBeNull();

      // Open the role select and choose "Org admin".
      await userEvent.click(screen.getByRole('combobox'));
      await userEvent.click(await screen.findByRole('option', { name: 'Org admin' }));

      await waitFor(() => {
        expect(seenRoles).toContain('org_admin');
      });
    });
  });

  describe('Data Display', () => {
    it('shows user external_id (DID) in row', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // DID should be displayed (possibly truncated) with title attribute
        const didElement = screen.getByTitle(mockUserFull.external_id);
        expect(didElement).toBeInTheDocument();
      });
    });

    it('truncates long DIDs appropriately', async () => {
      const longDid = 'did:polygonid:polygon:main:extremelylongidentifier1234567890abcdef';
      const userWithLongDid = createMockUser({
        id: 'user-long',
        external_id: longDid,
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithLongDid], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // The component truncates DIDs longer than 20 chars to: first 10 + ... + last 8
        // The full DID should be available in the title attribute
        const didElement = screen.getByTitle(longDid);
        expect(didElement).toBeInTheDocument();
        expect(didElement.textContent).toContain('...');
      });
    });

    it('shows correct number of rows', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: mockUsers, total: mockUsers.length, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // mockUsers has 3 users
        const rows = screen.getAllByRole('row');
        // +1 for header row
        expect(rows).toHaveLength(mockUsers.length + 1);
      });
    });
  });

  describe('Status Badges', () => {
    it('KYC true shows "Verified" with checkmark', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });
    });

    it('KYC false shows "No" indicator', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserNoKyc], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('No')).toBeInTheDocument();
      });
    });

    it('Banned user shows red "Banned" badge', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserBanned], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Banned')).toBeInTheDocument();
      });
    });

    it('Non-banned users show "Active" badge', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Active')).toBeInTheDocument();
      });
    });

    it('shows both KYC and ban status correctly for multiple users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull, mockUserNoKyc, mockUserBanned], total: 3, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // mockUserFull: KYC=true, banned=false
        // mockUserNoKyc: KYC=false, banned=false
        // mockUserBanned: KYC=true, banned=true
        expect(screen.getAllByText('Verified')).toHaveLength(2);
        expect(screen.getByText('No')).toBeInTheDocument();
        expect(screen.getAllByText('Active')).toHaveLength(2);
        expect(screen.getByText('Banned')).toBeInTheDocument();
      });
    });
  });

  describe('Actions', () => {
    it('clicking user row navigates to detail view', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      // Find the row by looking for its content and getting the parent row
      const rows = screen.getAllByRole('row');
      // First row is header, second is data row
      const dataRow = rows[1];
      await user.click(dataRow);

      expect(mockNavigate).toHaveBeenCalledWith(`/admin/rbac/users/${mockUserFull.id}`);
    });

    it('clicking ban button toggles user ban status', async () => {
      const user = userEvent.setup();

      let currentBanned = false;
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [
            { ...mockUserFull, banned: currentBanned },
          ], total: 1, limit: 25, offset: 0 });
        }),
        http.put('/api/v1/admin/users/:userId', async ({ request }) => {
          const body = (await request.json()) as { banned: boolean };
          currentBanned = body.banned;
          return HttpResponse.json({ ...mockUserFull, banned: currentBanned });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Ban')).toBeInTheDocument();
      });

      // Click ban button
      await user.click(screen.getByText('Ban'));

      await waitFor(() => {
        expect(screen.getByText('Unban')).toBeInTheDocument();
      });
    });

    it('clicking view button navigates to user detail', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      // Find and click the eye (view) button
      const viewButton = screen.getByTitle('View user details');
      await user.click(viewButton);

      expect(mockNavigate).toHaveBeenCalledWith(`/admin/rbac/users/${mockUserFull.id}`);
    });

    it('formats created date correctly', async () => {
      const userWithDate = createMockUser({
        id: 'user-date',
        created_at: '2024-03-15T10:30:00Z',
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithDate], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // The component formats dates like "Mar 15, 2024"
        expect(screen.getByText('Mar 15, 2024')).toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('shows empty list when API returns error', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
          );
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('No users found')).toBeInTheDocument();
      });
    });
  });

  describe('User Note Display', () => {
    it('shows user note when present', async () => {
      const userWithNote = createMockUser({
        id: 'user-note',
        note: 'VIP customer',
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithNote], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('VIP customer')).toBeInTheDocument();
      });
    });

    it('shows dash when note is empty', async () => {
      const userWithoutNote = createMockUser({
        id: 'user-no-note',
        note: '',
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithoutNote], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // Component shows '-' when note is empty/null
        expect(screen.getByText('-')).toBeInTheDocument();
      });
    });
  });

  describe('Ban/Unban Button States', () => {
    it('shows "Ban" button for active users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [{ ...mockUserFull, banned: false }], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        const banButton = screen.getByTitle('Ban this user');
        expect(banButton).toBeInTheDocument();
        expect(screen.getByText('Ban')).toBeInTheDocument();
      });
    });

    it('shows "Unban" button for banned users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [{ ...mockUserBanned, banned: true }], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        const unbanButton = screen.getByTitle('Unban this user');
        expect(unbanButton).toBeInTheDocument();
        expect(screen.getByText('Unban')).toBeInTheDocument();
      });
    });
  });
});
