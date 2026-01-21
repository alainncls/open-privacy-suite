import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Organization, Group, Role } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertCircle, Save, X, Loader2, Building2, FolderTree, Shield } from 'lucide-react';

interface MembershipFormProps {
  userId: string;
  organizations: Organization[];
  onClose: () => void;
  onSave: () => void;
}

export default function MembershipForm({
  userId,
  organizations,
  onClose,
  onSave,
}: MembershipFormProps) {
  const [selectedOrgId, setSelectedOrgId] = useState<string>('');
  const [groups, setGroups] = useState<Group[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<string>('');
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (selectedOrgId) {
      loadGroupsAndRoles();
    } else {
      setGroups([]);
      setRoles([]);
      setSelectedGroupId('');
    }
  }, [selectedOrgId]);

  const loadGroupsAndRoles = async () => {
    if (!selectedOrgId) return;

    setLoadingGroups(true);

    try {
      const [groupsRes, rolesRes] = await Promise.all([
        rbacApi.groups.list(selectedOrgId),
        rbacApi.roles.list(selectedOrgId),
      ]);
      setGroups(groupsRes.data || []);
      setRoles(rolesRes.data || []);
    } catch (error) {
      console.error('Failed to load groups/roles:', error);
      setGroups([]);
      setRoles([]);
    } finally {
      setLoadingGroups(false);
    }
  };

  // Get the role assigned to the selected group
  const selectedGroup = groups.find(g => g.id === selectedGroupId);
  const groupRole = selectedGroup?.role_id
    ? roles.find(r => r.id === selectedGroup.role_id)
    : null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await rbacApi.users.createMembership(userId, {
        group_id: selectedGroupId,
        // Role is now inherited from the group, not set per-membership
      });
      onSave();
    } catch (err: unknown) {
      console.error('Failed to create membership:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to create membership. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <span className="text-red-400 text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">Organization</label>
        <Select value={selectedOrgId} onValueChange={setSelectedOrgId}>
          <SelectTrigger>
            <SelectValue placeholder="Select organization" />
          </SelectTrigger>
          <SelectContent>
            {organizations.map(org => (
              <SelectItem key={org.id} value={org.id}>
                <div className="flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-white/40" />
                  <span>{org.name}</span>
                  <span className="text-white/40 text-xs">({org.slug})</span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">Group</label>
        {loadingGroups ? (
          <div className="flex items-center gap-2 text-white/40 py-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Loading groups...</span>
          </div>
        ) : !selectedOrgId ? (
          <p className="text-white/40 text-sm py-2">Select an organization first</p>
        ) : groups.length === 0 ? (
          <p className="text-white/40 text-sm py-2">No groups in this organization</p>
        ) : (
          <Select
            value={selectedGroupId}
            onValueChange={setSelectedGroupId}
            disabled={!selectedOrgId}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select group" />
            </SelectTrigger>
            <SelectContent>
              {groups.map(group => (
                <SelectItem key={group.id} value={group.id}>
                  <div className="flex items-center gap-2">
                    <FolderTree className="w-4 h-4 text-white/40" />
                    <span>{group.name}</span>
                    <span className="text-white/40 text-xs font-mono">({group.path})</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Show assigned role info */}
      {selectedGroupId && (
        <div className="p-3 rounded-lg bg-white/5 border border-white/10">
          <p className="text-xs text-white/50 mb-2">Assigned Role (inherited from group):</p>
          {groupRole ? (
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary-400" />
              <span className="font-medium">{groupRole.name}</span>
              {groupRole.description && (
                <span className="text-white/40 text-xs">- {groupRole.description}</span>
              )}
            </div>
          ) : (
            <span className="text-white/40 text-sm">No role assigned to this group</span>
          )}
          <p className="text-xs text-white/40 mt-2">
            Users inherit their role from the group. To change the role, edit the group settings.
          </p>
        </div>
      )}

      <div className="flex justify-end gap-3 pt-2">
        <Button
          type="button"
          variant="ghost"
          onClick={onClose}
          disabled={saving}
          className="gap-2"
        >
          <X className="w-4 h-4" />
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={saving || !selectedGroupId}
          className="gap-2"
        >
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Adding...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              Add Membership
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
