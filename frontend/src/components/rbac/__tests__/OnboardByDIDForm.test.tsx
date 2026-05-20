import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import OnboardByDIDForm from '../OnboardByDIDForm';
import { mockGroup, mockChildGroup } from '@/test/mocks/handlers';

// A plausible DID — long enough to pass the local validator and in the
// shape the backend accepts.
const VALID_DID = 'did:iden3:privado:main:2qABCDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHi';

function renderForm(
  props: Partial<React.ComponentProps<typeof OnboardByDIDForm>> = {}
) {
  const defaultProps: React.ComponentProps<typeof OnboardByDIDForm> = {
    orgId: 'org-1',
    groups: [mockGroup, mockChildGroup],
    onClose: vi.fn(),
    onSave: vi.fn(),
  };
  return render(<OnboardByDIDForm {...defaultProps} {...props} />);
}

async function selectGroup(
  user: ReturnType<typeof userEvent.setup>,
  optionPattern: RegExp
) {
  const combobox = screen.getByRole('combobox');
  await user.click(combobox);
  await waitFor(() => {
    expect(screen.getByRole('option', { name: optionPattern })).toBeInTheDocument();
  });
  await user.click(screen.getByRole('option', { name: optionPattern }));
}

describe('OnboardByDIDForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Form rendering', () => {
    it('renders DID input, group select, and onboard button', () => {
      renderForm();

      expect(screen.getByLabelText(/User DID/i)).toBeInTheDocument();
      expect(screen.getByText('Group')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Cancel/i })).toBeInTheDocument();
    });

    it('renders provided groups in the dropdown', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.click(screen.getByRole('combobox'));

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });
    });

    it('fetches groups when not supplied via props', async () => {
      let called = false;
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          called = true;
          return HttpResponse.json({
            data: [{ group: mockGroup, access: null }],
            total: 1,
            limit: 50,
            offset: 0,
          });
        })
      );

      renderForm({ groups: undefined });

      await waitFor(() => {
        expect(called).toBe(true);
      });
    });
  });

  describe('Local DID validation', () => {
    it('disables submit when DID is empty', () => {
      renderForm();
      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });

    it('disables submit for too-short DID', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), 'did:short');
      // Even after picking a group, the button stays disabled until the
      // DID looks valid.
      await selectGroup(user, /Root Group/i);

      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });

    it('disables submit for non-did: prefix', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.type(
        screen.getByLabelText(/User DID/i),
        'not-a-did:iden3:privado:main:xxxxxxxxxxxxxxxxxxxx'
      );
      await selectGroup(user, /Root Group/i);

      expect(screen.getByRole('button', { name: /Onboard user/i })).toBeDisabled();
    });

    it('enables submit once a valid DID and a group are selected', async () => {
      const user = userEvent.setup();
      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Onboard user/i })).not.toBeDisabled();
      });
    });
  });

  describe('Submission', () => {
    it('POSTs DID + group_id to /orgs/:orgId/memberships/by-did and calls onSave', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let captured: { did: string; group_id: string } | null = null;

      server.use(
        http.post(
          '/api/v1/admin/orgs/:orgId/memberships/by-did',
          async ({ request, params }) => {
            expect(params.orgId).toBe('org-1');
            captured = (await request.json()) as { did: string; group_id: string };
            return HttpResponse.json({
              membership: {
                id: 'membership-new',
                user_id: 'user-onboarded',
                group_id: captured.group_id,
                source: 'admin',
                zk_credential_ref: '',
                expires_at: null,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              },
              user_id: 'user-onboarded',
            });
          }
        )
      );

      renderForm({ onSave });

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(captured).not.toBeNull();
        expect(captured?.did).toBe(VALID_DID);
        expect(captured?.group_id).toBe('group-1');
        expect(onSave).toHaveBeenCalledTimes(1);
        expect(onSave).toHaveBeenCalledWith({
          userId: 'user-onboarded',
          membership: expect.objectContaining({
            id: 'membership-new',
            user_id: 'user-onboarded',
            group_id: 'group-1',
          }),
        });
      });
    });

    it('trims leading/trailing whitespace from the DID', async () => {
      const user = userEvent.setup();
      let captured: { did: string; group_id: string } | null = null;

      server.use(
        http.post(
          '/api/v1/admin/orgs/:orgId/memberships/by-did',
          async ({ request }) => {
            captured = (await request.json()) as { did: string; group_id: string };
            return HttpResponse.json({
              membership: {
                id: 'membership-new',
                user_id: 'user-onboarded',
                group_id: 'group-1',
                source: 'admin',
                zk_credential_ref: '',
                expires_at: null,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              },
              user_id: 'user-onboarded',
            });
          }
        )
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), `  ${VALID_DID}  `);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(captured?.did).toBe(VALID_DID);
      });
    });
  });

  describe('Error handling', () => {
    it('surfaces a friendly "already in group" message on 409', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json(
            { error: 'user is already a member of this group' },
            { status: 409 }
          );
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(
          screen.getByText('User is already a member of this group')
        ).toBeInTheDocument();
      });
    });

    it('surfaces an "access denied" message on 403 (caller not full-admin)', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json({ error: 'access denied' }, { status: 403 });
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(screen.getByText(/Access denied/i)).toBeInTheDocument();
      });
    });

    it('surfaces an "access denied" message on 403 (group in foreign org)', async () => {
      // Backend deliberately returns identical opaque strings for both
      // 403 paths; the UI must treat them the same.
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json(
            { error: 'access denied to target group' },
            { status: 403 }
          );
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(screen.getByText(/Access denied/i)).toBeInTheDocument();
      });
    });

    it('surfaces the backend error string on 400', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.json(
            { error: 'invalid request body' },
            { status: 400 }
          );
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(screen.getByText('invalid request body')).toBeInTheDocument();
      });
    });

    it('shows a generic error when the network call fails', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/memberships/by-did', () => {
          return HttpResponse.error();
        })
      );

      renderForm();

      await user.type(screen.getByLabelText(/User DID/i), VALID_DID);
      await selectGroup(user, /Root Group/i);
      await user.click(screen.getByRole('button', { name: /Onboard user/i }));

      await waitFor(() => {
        expect(
          screen.getByText('Failed to onboard user. Please try again.')
        ).toBeInTheDocument();
      });
    });
  });

  describe('Cancel', () => {
    it('calls onClose when cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderForm({ onClose });

      await user.click(screen.getByRole('button', { name: /Cancel/i }));

      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });
});
