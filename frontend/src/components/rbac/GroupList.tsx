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
                {group.is_org_admin && (
                  <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 gap-1 flex-shrink-0">
                    <Shield className="w-3 h-3" />
                    Org Admin
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-1 text-xs text-white/40 mt-0.5">
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
    </div>
  );
}
