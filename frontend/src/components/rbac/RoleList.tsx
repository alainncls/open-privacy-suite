import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Role } from '@/types/rbac';
import { CLAIM_LABELS } from '@/types/rbac';
import RoleForm from './RoleForm';
import { useOrgContext } from './RBACManager';
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
import { Shield, Plus, Pencil, Trash2, Loader2 } from 'lucide-react';

export default function RoleList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Role | null>(null);

  useEffect(() => {
    if (orgId) {
      loadRoles();
    }
  }, [orgId]);

  const loadRoles = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      const response = await rbacApi.roles.list(orgId);
      setRoles(response.data || []);
    } catch (error) {
      console.error('Failed to load roles:', error);
      setRoles([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (role: Role) => {
    if (!confirm(`Delete role "${role.name}"? This cannot be undone.`)) return;

    try {
      await rbacApi.roles.delete(orgId, role.id);
      await loadRoles();
    } catch (error) {
      console.error('Failed to delete role:', error);
      alert('Failed to delete role. It may be in use.');
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadRoles();
  };

  const getClaimColor = (claim: string) => {
    switch (claim) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'deployer':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'upgrade':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'writer':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'reader':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-white/10 text-white/60 border-white/20';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-white/80">Roles</h3>
          <p className="text-xs text-white/50 mt-0.5">
            Permission sets with claims (capabilities) assigned to users when they join groups
          </p>
        </div>
        <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
          <Plus className="w-4 h-4" />
          Add Role
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-white/40 animate-spin" />
        </div>
      ) : roles.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
            <Shield className="w-8 h-8 text-white/30" />
          </div>
          <p className="text-white/50 mb-4">No roles found</p>
          <Button
            variant="outline"
            onClick={() => setShowForm(true)}
            className="gap-2"
          >
            <Plus className="w-4 h-4" />
            Create your first role
          </Button>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Claims</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {roles.map((role, index) => (
              <TableRow
                key={role.id}
                className="animate-fade-in"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-primary-400" />
                    <span className="font-medium">{role.name}</span>
                  </div>
                </TableCell>
                <TableCell className="text-white/60 text-sm max-w-[200px] truncate">
                  {role.description || '-'}
                </TableCell>
                <TableCell>
                  {role.claims && role.claims.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {role.claims.map(claim => (
                        <Badge
                          key={claim}
                          variant="outline"
                          className={`text-xs ${getClaimColor(claim)}`}
                        >
                          {CLAIM_LABELS[claim] || claim}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-white/40 text-sm">No claims</span>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(role)}
                      title="Edit role"
                    >
                      <Pencil className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(role)}
                      className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                      title="Delete role"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* Create Role Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create Role</DialogTitle>
          </DialogHeader>
          <RoleForm orgId={orgId} onClose={() => setShowForm(false)} onSave={handleSave} />
        </DialogContent>
      </Dialog>

      {/* Edit Role Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Role</DialogTitle>
          </DialogHeader>
          {editing && (
            <RoleForm
              key={editing.id}
              orgId={orgId}
              role={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
