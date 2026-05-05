import { useEffect, useState } from 'react';
import type { Organization } from '@/types/rbac';
import { useOrgContext } from './RBACManager';
import OrganizationForm from './OrganizationForm';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import { rbacApi } from '@/api/rbac';
import Pagination from '@/components/ui/Pagination';
import {
  Building2,
  Plus,
  Pencil,
  Trash2,
  Loader2,
} from 'lucide-react';
import { useAdmin } from '@/components/auth/RequireAdmin';

const PAGE_SIZE = 25;

export default function OrganizationList() {
  const { refreshOrgs, setSelectedOrg } = useOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Organization | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Organization | null>(null);
  const [showDeleteError, setShowDeleteError] = useState(false);

  useEffect(() => {
    loadPage(0);
  }, []);

  const loadPage = async (newOffset: number = offset) => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list({ limit: PAGE_SIZE, offset: newOffset });
      const page = response.data;
      setOrganizations(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (error) {
      console.error('Failed to load organizations:', error);
      setOrganizations([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadPage();
    await refreshOrgs(); // Update the dropdown
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    try {
      await rbacApi.orgs.delete(deleteTarget.id);
      setDeleteTarget(null);
      await loadPage();
      await refreshOrgs(); // Update the dropdown
    } catch (error) {
      console.error('Failed to delete organization:', error);
      setDeleteTarget(null);
      setShowDeleteError(true);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Organizations</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Top-level tenants that contain groups and contracts
          </p>
        </div>
        {!isReadonlyAdmin && (
          <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
            <Plus className="w-4 h-4" />
            Add Organization
          </Button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : organizations.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <Building2 className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-4">No organizations found</p>
          {!isReadonlyAdmin && (
            <Button
              variant="outline"
              onClick={() => setShowForm(true)}
              className="gap-2"
            >
              <Plus className="w-4 h-4" />
              Create your first organization
            </Button>
          )}
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Slug</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {organizations.map((org, index) => (
              <TableRow
                key={org.id}
                className="animate-fade-in cursor-pointer"
                style={{ animationDelay: `${index * 30}ms` }}
                onClick={() => setSelectedOrg(org)}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-primary" />
                    <span className="font-medium">{org.name}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-xs">
                    {org.slug}
                  </Badge>
                </TableCell>
                <TableCell className="text-neutral-500 text-sm">
                  {formatDate(org.created_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    {!isReadonlyAdmin && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={e => {
                            e.stopPropagation();
                            setEditing(org);
                          }}
                          title="Edit organization"
                        >
                          <Pencil className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={e => {
                            e.stopPropagation();
                            setDeleteTarget(org);
                          }}
                          className="text-error-dark hover:text-error-dark hover:bg-error-light"
                          title="Delete organization"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onPageChange={(newOffset) => loadPage(newOffset)} />

      {/* Create Organization Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Organization</DialogTitle>
          </DialogHeader>
          <OrganizationForm
            onClose={() => setShowForm(false)}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Organization Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Organization</DialogTitle>
          </DialogHeader>
          {editing && (
            <OrganizationForm
              key={editing.id}
              organization={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Organization"
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={handleDeleteConfirm}
        variant="destructive"
      />

      {/* Delete Error Alert */}
      <AlertDialog
        open={showDeleteError}
        onOpenChange={setShowDeleteError}
        title="Delete Failed"
        description="Failed to delete organization. It may have groups or contracts that need to be deleted first."
        buttonLabel="OK"
        variant="error"
      />
    </div>
  );
}
