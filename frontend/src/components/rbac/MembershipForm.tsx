import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Organization, Group } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertCircle, Save, X, Loader2, Building2, FolderTree } from 'lucide-react';

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
  const [selectedGroupId, setSelectedGroupId] = useState<string>('');
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (selectedOrgId) {
      loadGroups();
    } else {
      setGroups([]);
      setSelectedGroupId('');
    }
  }, [selectedOrgId]);

  const loadGroups = async () => {
    if (!selectedOrgId) return;

    setLoadingGroups(true);

    try {
      const groupsRes = await rbacApi.groups.list(selectedOrgId);
      setGroups(groupsRes.data || []);
    } catch (error) {
      console.error('Failed to load groups:', error);
      setGroups([]);
    } finally {
      setLoadingGroups(false);
    }
  };

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
        <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">Organization</label>
        <Select value={selectedOrgId} onValueChange={setSelectedOrgId}>
          <SelectTrigger>
            <SelectValue placeholder="Select organization" />
          </SelectTrigger>
          <SelectContent>
            {organizations.map(org => (
              <SelectItem key={org.id} value={org.id}>
                <div className="flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-[#94A3B8]" />
                  <span>{org.name}</span>
                  <span className="text-[#94A3B8] text-xs">({org.slug})</span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">Group</label>
        {loadingGroups ? (
          <div className="flex items-center gap-2 text-[#94A3B8] py-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Loading groups...</span>
          </div>
        ) : !selectedOrgId ? (
          <p className="text-[#94A3B8] text-sm py-2">Select an organization first</p>
        ) : groups.length === 0 ? (
          <p className="text-[#94A3B8] text-sm py-2">No groups in this organization</p>
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
                    <FolderTree className="w-4 h-4 text-[#94A3B8]" />
                    <span>{group.name}</span>
                    <span className="text-[#94A3B8] text-xs font-mono">({group.path})</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Info about permissions */}
      {selectedGroupId && (
        <div className="p-3 rounded-lg bg-[#F5F3FF] border border-[#C4A8FD]">
          <p className="text-sm text-[#6B3DD4]">
            The user will inherit permissions from this group's access settings
            (allowed methods, claims, rate limits).
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
