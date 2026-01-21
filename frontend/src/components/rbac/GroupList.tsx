import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, GroupPermissions, Role } from '@/types/rbac';
import GroupForm from './GroupForm';
import GroupPermissionsForm from './GroupPermissionsForm';
import { useOrgContext } from './RBACManager';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  FolderTree,
  FolderOpen,
  Plus,
  Pencil,
  Trash2,
  Settings,
  Loader2,
  ChevronRight,
  Shield,
} from 'lucide-react';

interface GroupWithPermissions extends Group {
  permissions?: GroupPermissions | null;
  role?: Role | null;
}

export default function GroupList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [groups, setGroups] = useState<GroupWithPermissions[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Group | null>(null);
  const [editingPermissions, setEditingPermissions] = useState<Group | null>(null);
  const [parentForNew, setParentForNew] = useState<Group | null>(null);

  useEffect(() => {
    if (orgId) {
      loadGroups();
    }
  }, [orgId]);

  const loadGroups = async () => {
    if (!orgId) return;
    try {
      setLoading(true);

      // Load groups and roles in parallel
      const [groupsResponse, rolesResponse] = await Promise.all([
        rbacApi.groups.list(orgId),
        rbacApi.roles.list(orgId),
      ]);
      const groupsList = groupsResponse.data || [];
      const rolesList = rolesResponse.data || [];
      setRoles(rolesList);

      // Create a map of roles for quick lookup
      const rolesMap = new Map(rolesList.map(r => [r.id, r]));

      // Load permissions for each group
      const groupsWithPermissions = await Promise.all(
        groupsList.map(async group => {
          try {
            const permsResponse = await rbacApi.groups.getPermissions(
              orgId,
              group.id
            );
            return {
              ...group,
              permissions: permsResponse.data,
              role: group.role_id ? rolesMap.get(group.role_id) || null : null,
            };
          } catch {
            return {
              ...group,
              permissions: null,
              role: group.role_id ? rolesMap.get(group.role_id) || null : null,
            };
          }
        })
      );

      // Sort by path for hierarchical display
      groupsWithPermissions.sort((a, b) => a.path.localeCompare(b.path));
      setGroups(groupsWithPermissions);
    } catch (error) {
      console.error('Failed to load groups:', error);
      setGroups([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (group: Group) => {
    if (!confirm(`Delete group "${group.name}"? This will also delete all child groups.`))
      return;

    try {
      await rbacApi.groups.delete(orgId, group.id);
      await loadGroups();
    } catch (error) {
      console.error('Failed to delete group:', error);
      alert('Failed to delete group. It may have members or child groups.');
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    setParentForNew(null);
    await loadGroups();
  };

  const handlePermissionsSave = async () => {
    setEditingPermissions(null);
    await loadGroups();
  };

  const handleAddChild = (parent: Group) => {
    setParentForNew(parent);
    setShowForm(true);
  };

  // Group groups by parent for tree rendering
  const getRootGroups = () => groups.filter(g => !g.parent_id);

  const getChildGroups = (parentId: string) =>
    groups.filter(g => g.parent_id === parentId);

  const renderGroup = (group: GroupWithPermissions, level: number = 0) => {
    const children = getChildGroups(group.id);
    const hasAddresses =
      group.permissions &&
      (group.permissions.allow_addresses?.length || 0) > 0;

    return (
      <div key={group.id} className="animate-fade-in">
        <div
          className={`flex items-center gap-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors ${
            level > 0 ? 'ml-6 border-l-2 border-white/10' : ''
          }`}
        >
          <div
            className="flex items-center gap-2 flex-1 min-w-0"
            style={{ paddingLeft: `${level * 8}px` }}
          >
            {children.length > 0 ? (
              <FolderOpen className="w-5 h-5 text-primary-400 flex-shrink-0" />
            ) : (
              <FolderTree className="w-5 h-5 text-primary-400 flex-shrink-0" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium truncate">{group.name}</span>
                <Badge variant="outline" className="font-mono text-xs flex-shrink-0">
                  {group.slug}
                </Badge>
                {group.role && (
                  <Badge variant="secondary" className="text-xs flex-shrink-0 gap-1">
                    <Shield className="w-3 h-3" />
                    {group.role.name}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1 text-xs text-white/40 mt-0.5">
                <span className="font-mono">{group.path}</span>
                {hasAddresses && (
                  <>
                    <ChevronRight className="w-3 h-3" />
                    <span>
                      {group.permissions?.allow_addresses?.length || 0} addresses
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-1 flex-shrink-0">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleAddChild(group)}
              title="Add child group"
            >
              <Plus className="w-4 h-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setEditingPermissions(group)}
              title="Edit permissions"
            >
              <Settings className="w-4 h-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setEditing(group)}
              title="Edit group"
            >
              <Pencil className="w-4 h-4" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleDelete(group)}
              className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
              title="Delete group"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {children.length > 0 && (
          <div className="mt-2 space-y-2">
            {children.map(child => renderGroup(child as GroupWithPermissions, level + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-white/80">Groups</h3>
          <p className="text-xs text-white/50 mt-0.5">
            Hierarchical containers defining what methods and addresses users can access
          </p>
        </div>
        <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
          <Plus className="w-4 h-4" />
          Add Group
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-white/40 animate-spin" />
        </div>
      ) : groups.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
            <FolderTree className="w-8 h-8 text-white/30" />
          </div>
          <p className="text-white/50 mb-4">No groups found</p>
          <Button
            variant="outline"
            onClick={() => setShowForm(true)}
            className="gap-2"
          >
            <Plus className="w-4 h-4" />
            Create your first group
          </Button>
        </div>
      ) : (
        <div className="space-y-2">{getRootGroups().map(g => renderGroup(g))}</div>
      )}

      {/* Create Group Dialog */}
      <Dialog
        open={showForm}
        onOpenChange={open => {
          setShowForm(open);
          if (!open) setParentForNew(null);
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {parentForNew
                ? `Add child group to "${parentForNew.name}"`
                : 'Create Group'}
            </DialogTitle>
          </DialogHeader>
          <GroupForm
            orgId={orgId}
            groups={groups}
            roles={roles}
            parentId={parentForNew?.id}
            onClose={() => {
              setShowForm(false);
              setParentForNew(null);
            }}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Group Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Group</DialogTitle>
          </DialogHeader>
          {editing && (
            <GroupForm
              key={editing.id}
              orgId={orgId}
              groups={groups}
              roles={roles}
              group={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Edit Permissions Dialog */}
      <Dialog
        open={!!editingPermissions}
        onOpenChange={open => !open && setEditingPermissions(null)}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              Edit Permissions for "{editingPermissions?.name}"
            </DialogTitle>
          </DialogHeader>
          {editingPermissions && (
            <GroupPermissionsForm
              orgId={orgId}
              groupId={editingPermissions.id}
              onClose={() => setEditingPermissions(null)}
              onSave={handlePermissionsSave}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
