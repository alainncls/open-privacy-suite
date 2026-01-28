import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import PreregisterForm from '../PreregisterForm';

// Helper to render form with default props
function renderPreregisterForm(props: {
  orgId?: string;
  onClose?: () => void;
  onSave?: () => void;
} = {}) {
  const defaultProps = {
    orgId: 'org-1',
    onClose: vi.fn(),
    onSave: vi.fn(),
    ...props,
  };

  return {
    ...render(<PreregisterForm {...defaultProps} />),
    onClose: defaultProps.onClose,
    onSave: defaultProps.onSave,
  };
}

// Default handler that returns a deployed factory to skip the "deploy factory" UI in dev mode
function useDeployedFactoryHandler() {
  server.use(
    http.get('/api/v1/dev/create3-factory', () => {
      return HttpResponse.json({
        address: '0x1234567890123456789012345678901234567890',
        deployed: true,
      });
    })
  );
}

describe('PreregisterForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // By default, return a deployed factory so the form shows
    useDeployedFactoryHandler();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Form Rendering', () => {
    it('renders factory address field', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });
    });

    it('renders salt prefix field', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Salt Prefix')).toBeInTheDocument();
      });
      expect(screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef')).toBeInTheDocument();
    });

    it('renders count field with default value', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Count')).toBeInTheDocument();
      });

      const countInput = screen.getByRole('spinbutton');
      expect(countInput).toHaveValue(10);
    });

    it('renders note field (optional)', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Note (optional)')).toBeInTheDocument();
      });
      expect(screen.getByPlaceholderText('e.g., Implementation contracts for v2 upgrade')).toBeInTheDocument();
    });

    it('shows informational tip about CREATE3', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText(/How it works:/)).toBeInTheDocument();
      });
      expect(screen.getByText(/CREATE3 addresses are deterministic/)).toBeInTheDocument();
    });

    it('renders Cancel button', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Cancel')).toBeInTheDocument();
      });
    });

    it('renders submit button with count', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText(/Pre-register 10 Addresses/)).toBeInTheDocument();
      });
    });
  });

  describe('Form Validation', () => {
    it('validates factory address is required', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      const factoryInput = screen.getByPlaceholderText('0x...');
      expect(factoryInput).toHaveAttribute('required');
    });

    it('validates factory address format (0x + 40 hex chars)', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      const factoryInput = screen.getByPlaceholderText('0x...');
      expect(factoryInput).toHaveAttribute('pattern', '^0x[a-fA-F0-9]{40}$');
      // In dev mode with factory deployed, the input is disabled and pre-filled
      // We just verify the pattern attribute is set correctly
    });

    it('validates salt prefix is required', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Salt Prefix')).toBeInTheDocument();
      });

      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      expect(saltInput).toHaveAttribute('required');
    });

    it('validates count minimum (1)', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Count')).toBeInTheDocument();
      });

      const countInput = screen.getByRole('spinbutton');
      expect(countInput).toHaveAttribute('min', '1');
    });

    it('validates count maximum (100)', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Count')).toBeInTheDocument();
      });

      const countInput = screen.getByRole('spinbutton');
      expect(countInput).toHaveAttribute('max', '100');
    });

    it('submit button is disabled when salt is empty', async () => {
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText(/Pre-register 10 Addresses/)).toBeInTheDocument();
      });

      // Button should be disabled because salt is empty (factory is pre-filled in dev mode)
      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      expect(submitButton).toBeDisabled();
    });

    it('submit button is enabled when form is valid', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is already pre-filled in dev mode, so just fill in the salt
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      expect(submitButton).not.toBeDisabled();
    });
  });

  describe('Form Submission', () => {
    it('submits POST to /orgs/:id/addresses/preregister', async () => {
      const user = userEvent.setup();
      const { onSave } = renderPreregisterForm();

      let receivedRequest: { factory: string; salt_prefix: string; count: number; note?: string } | null = null;
      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', async ({ request, params }) => {
          receivedRequest = await request.json() as typeof receivedRequest;
          expect(params.orgId).toBe('org-1');
          return HttpResponse.json({
            addresses: [
              {
                id: 'preregistered-new-0',
                org_id: 'org-1',
                address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                factory: receivedRequest!.factory,
                salt: receivedRequest!.salt_prefix,
                note: receivedRequest!.note,
                created_at: new Date().toISOString(),
                used_at: null,
              },
            ],
          });
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode from the deployed factory endpoint
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      const noteInput = screen.getByPlaceholderText('e.g., Implementation contracts for v2 upgrade');

      await user.type(saltInput, 'myapp-v1');
      await user.type(noteInput, 'Test note');

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      // Factory is pre-filled from the dev endpoint
      expect(receivedRequest?.factory).toBe('0x1234567890123456789012345678901234567890');
      expect(receivedRequest?.salt_prefix).toBe('0xmyapp-v1');
      expect(receivedRequest?.count).toBe(10);
      expect(receivedRequest?.note).toBe('Test note');
    });

    it('prepends 0x to salt if not present', async () => {
      const user = userEvent.setup();
      const { onSave } = renderPreregisterForm();

      let receivedRequest: { salt_prefix: string } | null = null;
      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', async ({ request }) => {
          receivedRequest = await request.json() as typeof receivedRequest;
          return HttpResponse.json({ addresses: [] });
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'mysalt'); // No 0x prefix

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(receivedRequest?.salt_prefix).toBe('0xmysalt');
    });

    it('does not prepend 0x if salt already has it', async () => {
      const user = userEvent.setup();
      const { onSave } = renderPreregisterForm();

      let receivedRequest: { salt_prefix: string } | null = null;
      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', async ({ request }) => {
          receivedRequest = await request.json() as typeof receivedRequest;
          return HttpResponse.json({ addresses: [] });
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, '0xdeadbeef'); // Already has 0x prefix

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(receivedRequest?.salt_prefix).toBe('0xdeadbeef');
    });

    it('shows loading state while saving', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      // Make the request hang
      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', async () => {
          await new Promise(() => {}); // Never resolves
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Generating...')).toBeInTheDocument();
      });
    });

    it('disables buttons while saving', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      // Make the request hang
      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', async () => {
          await new Promise(() => {}); // Never resolves
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      const cancelButton = screen.getByRole('button', { name: /Cancel/ });

      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Generating...')).toBeInTheDocument();
      });

      expect(cancelButton).toBeDisabled();
    });
  });

  describe('Error Handling', () => {
    it('shows error message on failure', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', () => {
          return HttpResponse.json(
            { error: 'Invalid factory address' },
            { status: 400 }
          );
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Invalid factory address')).toBeInTheDocument();
      });
    });

    it('shows generic error when no specific error message', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      server.use(
        http.post('/api/v1/orgs/:orgId/addresses/preregister', () => {
          return HttpResponse.json({}, { status: 500 });
        })
      );

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const submitButton = screen.getByRole('button', { name: /Pre-register/ });
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Failed to preregister addresses. Please try again.')).toBeInTheDocument();
      });
    });
  });

  describe('Cancel Button', () => {
    it('calls onClose when Cancel button is clicked', async () => {
      const user = userEvent.setup();
      const { onClose } = renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Cancel')).toBeInTheDocument();
      });

      const cancelButton = screen.getByRole('button', { name: /Cancel/ });
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe('Address Preview', () => {
    it('shows preview toggle when form is valid', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      await waitFor(() => {
        expect(screen.getByText(/Show address preview/)).toBeInTheDocument();
      });
    });

    it('toggles preview on click', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const previewButton = await screen.findByText(/Show address preview/);
      await user.click(previewButton);

      await waitFor(() => {
        expect(screen.getByText(/Hide address preview/)).toBeInTheDocument();
      });
      expect(screen.getByText(/Addresses will be generated server-side/)).toBeInTheDocument();
    });

    it('shows "and X more" when count > 5', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });

      // Factory is pre-filled in dev mode
      const saltInput = screen.getByPlaceholderText('e.g., myapp-v1 or 0xdeadbeef');
      await user.type(saltInput, 'myapp-v1');

      const previewButton = await screen.findByText(/Show address preview/);
      await user.click(previewButton);

      await waitFor(() => {
        // Default count is 10, so should show "... and 5 more"
        expect(screen.getByText(/and 5 more/)).toBeInTheDocument();
      });
    });
  });

  describe('Count Field Updates', () => {
    it('updates button text when count changes', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText(/Pre-register 10 Addresses/)).toBeInTheDocument();
      });

      const countInput = screen.getByRole('spinbutton');
      await user.clear(countInput);
      await user.type(countInput, '1');

      await waitFor(() => {
        expect(screen.getByText(/Pre-register 1 Address$/)).toBeInTheDocument();
      });
    });

    it('shows singular "Address" when count is 1', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Count')).toBeInTheDocument();
      });

      const countInput = screen.getByRole('spinbutton');
      await user.clear(countInput);
      await user.type(countInput, '1');

      await waitFor(() => {
        expect(screen.getByText(/Pre-register 1 Address$/)).toBeInTheDocument();
      });
    });

    it('shows plural "Addresses" when count > 1', async () => {
      const user = userEvent.setup();
      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Count')).toBeInTheDocument();
      });

      const countInput = screen.getByRole('spinbutton');
      await user.clear(countInput);
      await user.type(countInput, '5');

      await waitFor(() => {
        expect(screen.getByText(/Pre-register 5 Addresses/)).toBeInTheDocument();
      });
    });
  });

  describe('Dev Mode Factory Deployment', () => {
    it('shows deploy factory UI when no factory is deployed', async () => {
      // Override the default handler to return no factory
      server.use(
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({ error: 'Not deployed' }, { status: 404 });
        })
      );

      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Development Mode')).toBeInTheDocument();
      });
      expect(screen.getByText(/No CREATE3 factory contract is deployed/)).toBeInTheDocument();
      expect(screen.getByText('Deploy CREATE3 Factory')).toBeInTheDocument();
    });

    it('shows loading state when checking factory', async () => {
      // Make the factory check hang to see loading state
      server.use(
        http.get('/api/v1/dev/create3-factory', async () => {
          await new Promise(() => {}); // Never resolves
        })
      );

      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Checking CREATE3 factory...')).toBeInTheDocument();
      });
    });

    it('deploys factory on button click', async () => {
      const user = userEvent.setup();

      // Start with no factory
      server.use(
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({ error: 'Not deployed' }, { status: 404 });
        }),
        http.post('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({
            address: '0xdeployedFactoryAddress1234567890123456',
            deployed: true,
          });
        })
      );

      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Deploy CREATE3 Factory')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Deploy CREATE3 Factory'));

      await waitFor(() => {
        // After deployment, the form should show with factory pre-filled
        expect(screen.getByText('Factory Address')).toBeInTheDocument();
      });
    });

    it('shows error when factory deployment fails', async () => {
      const user = userEvent.setup();

      // Start with no factory
      server.use(
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({ error: 'Not deployed' }, { status: 404 });
        }),
        http.post('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json(
            { error: 'Failed to deploy factory' },
            { status: 500 }
          );
        })
      );

      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Deploy CREATE3 Factory')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Deploy CREATE3 Factory'));

      await waitFor(() => {
        expect(screen.getByText('Failed to deploy factory')).toBeInTheDocument();
      });
    });

    it('allows entering custom factory address in dev mode', async () => {
      const user = userEvent.setup();

      // Start with no factory
      server.use(
        http.get('/api/v1/dev/create3-factory', () => {
          return HttpResponse.json({ error: 'Not deployed' }, { status: 404 });
        })
      );

      renderPreregisterForm();

      await waitFor(() => {
        expect(screen.getByText('Use Existing Factory Address')).toBeInTheDocument();
      });

      const factoryInput = screen.getByPlaceholderText('0x...');
      await user.type(factoryInput, '0xcustom12345678901234567890123456789012');

      // After entering a valid address, the form should switch to the regular form view
      await waitFor(() => {
        expect(screen.getByText('Salt Prefix')).toBeInTheDocument();
      });
    });
  });
});
