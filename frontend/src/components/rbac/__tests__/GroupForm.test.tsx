import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import GroupForm from '../GroupForm';
import { mockGroup, mockChildGroup } from '@/test/mocks/handlers';
import { mockGroupHierarchy } from '@/test/mocks/rbac-fixtures';

// Mock hasPointerCapture for Radix UI Select in JSDOM
beforeAll(() => {
  Element.prototype.hasPointerCapture = vi.fn().mockReturnValue(false);
  Element.prototype.setPointerCapture = vi.fn();
  Element.prototype.releasePointerCapture = vi.fn();
});

afterAll(() => {
  vi.restoreAllMocks();
});

// Minimal wrapper since GroupForm doesn't need org context directly
function renderGroupForm(props: {
  orgId?: string;
  groups?: typeof mockGroupHierarchy;
  group?: typeof mockGroup;
  parentId?: string;
  onClose?: () => void;
  onSave?: () => void;
}) {
  const defaultProps = {
    orgId: 'org-1',
    groups: [],
    onClose: vi.fn(),
    onSave: vi.fn(),
  };

  return render(<GroupForm {...defaultProps} {...props} />);
}

describe('GroupForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Create Mode', () => {
    it('shows empty form fields', () => {
      renderGroupForm({});

      // Name field should be empty
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      expect(nameInput).toHaveValue('');

      // Slug field should be empty
      const slugInput = screen.getByPlaceholderText(/engineering/);
      expect(slugInput).toHaveValue('');
    });

    it('parent dropdown is rendered with combobox role', async () => {
      renderGroupForm({
        groups: mockGroupHierarchy,
      });

      // Verify the parent dropdown trigger is rendered
      const parentTrigger = screen.getByRole('combobox');
      expect(parentTrigger).toBeInTheDocument();

      // The select should have default placeholder text (multiple elements possible due to hidden select)
      const placeholders = screen.getAllByText('No parent (root level)');
      expect(placeholders.length).toBeGreaterThan(0);
    });

    it('validates name is required', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      renderGroupForm({ onSave });

      // Fill in slug but not name
      const slugInput = screen.getByPlaceholderText(/engineering/);
      await user.type(slugInput, 'test_slug');

      // Try to submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      // onSave should not have been called (form validation failed)
      expect(onSave).not.toHaveBeenCalled();
    });

    it('validates slug is required', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      renderGroupForm({ onSave });

      // Fill in name but clear auto-generated slug
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Test Group');

      // Clear the auto-generated slug
      const slugInput = screen.getByPlaceholderText(/engineering/);
      await user.clear(slugInput);

      // Try to submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      // onSave should not have been called (form validation failed)
      expect(onSave).not.toHaveBeenCalled();
    });

    it('submits POST with parent_id if selected', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroup,
            id: 'group-new',
            parent_id: capturedBody.parent_id,
          });
        })
      );

      renderGroupForm({
        groups: mockGroupHierarchy,
        onSave,
      });

      // Fill in name
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'New Team');

      // Select a parent using the combobox
      const parentTrigger = screen.getByRole('combobox');
      await user.click(parentTrigger);

      await waitFor(() => {
        expect(screen.getByText('Engineering')).toBeInTheDocument();
      });

      // Click on Engineering option
      await user.click(screen.getByText('Engineering'));

      // Submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        parent_id: 'group-engineering',
      });
    });

    it('root group has null parent_id', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroup,
            id: 'group-new',
          });
        })
      );

      renderGroupForm({
        groups: mockGroupHierarchy,
        onSave,
      });

      // Fill in name (no parent selected = root level)
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Root Team');

      // Submit without selecting a parent
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        parent_id: null,
      });
    });

    it('auto-generates slug from name', async () => {
      const user = userEvent.setup();

      renderGroupForm({});

      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'My Test Group');

      const slugInput = screen.getByPlaceholderText(/engineering/);
      expect(slugInput).toHaveValue('my_test_group');
    });

    it('shows path preview with parent', async () => {
      const user = userEvent.setup();

      renderGroupForm({
        groups: mockGroupHierarchy,
      });

      // Fill in name
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'New Team');

      // Select a parent
      const parentTrigger = screen.getByRole('combobox');
      await user.click(parentTrigger);

      await waitFor(() => {
        expect(screen.getByText('Engineering')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Engineering'));

      // Check path preview
      await waitFor(() => {
        expect(screen.getByText('root.engineering.new_team')).toBeInTheDocument();
      });
    });
  });

  describe('Edit Mode', () => {
    it('populates with existing group data', () => {
      renderGroupForm({
        group: mockGroup,
        groups: [],
      });

      // Name should be populated
      expect(screen.getByDisplayValue('Root Group')).toBeInTheDocument();

      // Slug field should not be shown in edit mode
      expect(screen.queryByPlaceholderText(/engineering/)).not.toBeInTheDocument();
    });

    it('shows current parent in edit mode', () => {
      renderGroupForm({
        group: mockChildGroup,
        groups: [mockGroup, mockChildGroup],
      });

      // The name should be populated
      expect(screen.getByDisplayValue('Engineering')).toBeInTheDocument();
    });

    it('shows Update button in edit mode', () => {
      renderGroupForm({
        group: mockGroup,
        groups: [],
      });

      expect(screen.getByText('Update Group')).toBeInTheDocument();
    });

    it('submits PUT request in edit mode', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroup,
            name: capturedBody.name,
          });
        })
      );

      renderGroupForm({
        group: mockGroup,
        groups: [],
        onSave,
      });

      // Change the name
      const nameInput = screen.getByDisplayValue('Root Group');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Root');

      // Submit
      const submitButton = screen.getByText('Update Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        name: 'Updated Root',
      });
    });
  });

  describe('Organization Admin Toggle', () => {
    it('shows org admin toggle', () => {
      renderGroupForm({});

      expect(screen.getByText('Organization Admin')).toBeInTheDocument();
    });

    it('can toggle org admin status', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockGroup);
        })
      );

      renderGroupForm({ onSave });

      // Fill required fields
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Admin Team');

      // Toggle org admin
      const orgAdminLabel = screen.getByText('Organization Admin').closest('label');
      if (orgAdminLabel) {
        await user.click(orgAdminLabel);
      }

      // Submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        is_org_admin: true,
      });
    });
  });

  describe('Error Handling', () => {
    it('shows error message on save failure', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json(
            { error: 'Slug already exists' },
            { status: 400 }
          );
        })
      );

      renderGroupForm({});

      // Fill in form
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Test Group');

      // Submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Slug already exists')).toBeInTheDocument();
      });
    });
  });

  describe('Cancel Button', () => {
    it('calls onClose when Cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderGroupForm({ onClose });

      const cancelButton = screen.getByText('Cancel');
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe('Pre-selected Parent', () => {
    it('uses parentId prop when provided', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockGroup);
        })
      );

      renderGroupForm({
        groups: mockGroupHierarchy,
        parentId: 'group-engineering',
        onSave,
      });

      // Fill in name
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Sub Team');

      // Submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        parent_id: 'group-engineering',
      });
    });
  });
});
