import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, GroupAccess } from '@/types/rbac';
import GroupForm from './GroupForm';
import GroupAccessForm from './GroupAccessForm';
import { useOrgContext } from './RBACManager';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
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

interface GroupWithAccess extends Group {
  access?: GroupAccess | null;
}

export default function GroupList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [groups, setGroups] = useState<GroupWithAccess[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Group | null>(null);
  const [editingAccess, setEditingAccess] = useState<Group | null>(null);
  const [parentForNew, setParentForNew] = useState<Group | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Group | null>(null);
  const [showDeleteError, setShowDeleteError] = useState(false);

  useEffect(() => {
    if (orgId) {
      loadGroups();
    }
  }, [orgId]);

  const loadGroups = async () => {
    if (!orgId) return;
    try {
      setLoading(true);

      const groupsResponse = await rbacApi.groups.list(orgId);
      const groupsList = groupsResponse.data || [];

      // Load access settings for each group
      const groupsWithAccess = await Promise.all(
        groupsList.map(async group => {
          try {
            const accessResponse = await rbacApi.groups.getAccess(
              orgId,
              group.id
            );
            return {
              ...group,
              access: accessResponse.data,
            };
          } catch {
            return {
              ...group,
              access: null,
            };
          }
        })
      );

      // Sort by path for hierarchical display
      groupsWithAccess.sort((a, b) => a.path.localeCompare(b.path));
      setGroups(groupsWithAccess);
    } catch (error) {
      console.error('Failed to load groups:', error);
      setGroups([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;

    try {
      await rbacApi.groups.delete(orgId, deleteTarget.id);
      setDeleteTarget(null);
      await loadGroups();
    } catch (error) {
      console.error('Failed to delete group:', error);
      setDeleteTarget(null);
      setShowDeleteError(true);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    setParentForNew(null);
    await loadGroups();
  };

  const handleAccessSave = async () => {
    setEditingAccess(null);
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

  const renderGroup = (group: GroupWithAccess, level: number = 0) => {
    const children = getChildGroups(group.id);
    const hasMethods =
      group.access &&
      (group.access.allowed_methods?.length || 0) > 0;

    return (
      <div key={group.id} className="animate-fade-in">
        <div
          className={`flex items-center gap-3 p-3 rounded-lg bg-[#F1F5F9] hover:bg-[#F5F3FF] transition-colors ${
            level > 0 ? 'ml-6 border-l-2 border-[#E2E8F0]' : ''
          }`}
        >
          <div
            className="flex items-center gap-2 flex-1 min-w-0"
            style={{ paddingLeft: `${level * 8}px` }}
          >
            {children.length > 0 ? (
              <FolderOpen className="w-5 h-5 text-[#8950FA] flex-shrink-0" />
            ) : (
              <FolderTree className="w-5 h-5 text-[#8950FA] flex-shrink-0" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium truncate text-[#0F0F0F]">{group.name}</span>
                <Badge variant="outline" className="font-mono text-xs flex-shrink-0">
                  {group.slug}
                </Badge>
                {group.is_org_admin && (
                  <Badge className="bg-[#FEF9C3] text-[#854D0E] border-[#FDE047] gap-1 flex-shrink-0">
                    <Shield className="w-3 h-3" />
                    Org Admin
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1 text-xs text-[#94A3B8] mt-0.5">
                <span className="font-mono">{group.path}</span>
                {hasMethods && (
                  <>
                    <ChevronRight className="w-3 h-3" />
                    <span>
                      {group.access?.allowed_methods?.length || 0} methods
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
              onClick={() => setEditingAccess(group)}
              title="Edit access settings"
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
              onClick={() => setDeleteTarget(group)}
              className="text-[#991B1B] hover:text-[#7F1D1D] hover:bg-[#FEE2E2]"
              title="Delete group"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {children.length > 0 && (
          <div className="mt-2 space-y-2">
            {children.map(child => renderGroup(child as GroupWithAccess, level + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-[#374151]">Groups</h3>
          <p className="text-xs text-[#6B7280] mt-0.5">
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
          <Loader2 className="w-6 h-6 text-[#94A3B8] animate-spin" />
        </div>
      ) : groups.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <FolderTree className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-4">No groups found</p>
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
              group={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Edit Access Dialog */}
      <Dialog
        open={!!editingAccess}
        onOpenChange={open => !open && setEditingAccess(null)}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              Edit Access for "{editingAccess?.name}"
            </DialogTitle>
          </DialogHeader>
          {editingAccess && (
            <GroupAccessForm
              orgId={orgId}
              groupId={editingAccess.id}
              onClose={() => setEditingAccess(null)}
              onSave={handleAccessSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Group"
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This will also delete all child groups.`}
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
        description="Failed to delete group. It may have members or child groups that need to be removed first."
        buttonLabel="OK"
        variant="error"
      />
    </div>
  );
}
