import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, ContractGrant, CreateContractGrantInput } from '@/types/rbac';
import { CLAIM_LABELS } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { AlertCircle, Save, X, Loader2, Users } from 'lucide-react';

interface ContractGrantFormProps {
  orgId: string;
  contractAddress: string;
  grant?: ContractGrant | null; // If provided, we're viewing (read-only since grants are simple links)
  groups: Group[];
  existingGrantGroupIds: string[]; // Groups that already have grants (for filtering)
  onClose: () => void;
  onSave: () => void;
}

export default function ContractGrantForm({
  orgId,
  contractAddress,
  grant,
  groups,
  existingGrantGroupIds,
  onClose,
  onSave,
}: ContractGrantFormProps) {
  const [selectedGroupId, setSelectedGroupId] = useState<string>(grant?.group_id || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!grant;

  // Available groups (exclude ones that already have grants)
  const availableGroups = groups.filter(g => !existingGrantGroupIds.includes(g.id));

  // Get the selected group's details to show its claims
  const selectedGroup = groups.find(g => g.id === selectedGroupId);
  const grantGroup = grant ? groups.find(g => g.id === grant.group_id) : null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    setSaving(true);

    try {
      // When creating a grant, we just link the group to the contract
      // The group's default_claims (from group access) determine permissions
      const input: CreateContractGrantInput = {
        group_id: selectedGroupId,
        // Claims are optional - if not provided, the group's default_claims apply
        // We pass an empty array to indicate "use group's claims"
        claims: [],
      };
      await rbacApi.contracts.createGrant(orgId, contractAddress, input);
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save grant:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save grant. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  // If editing, show read-only view (grants are simple links - delete and recreate to change)
  if (isEditing && grantGroup) {
    return (
      <div className="space-y-5">
        <div className="p-4 rounded-lg bg-[#F5F3FF] border border-[#E9E3FF]">
          <div className="flex items-center gap-3">
            <Users className="w-5 h-5 text-[#8950FA]" />
            <div>
              <p className="font-medium text-[#0F0F0F]">{grantGroup.name}</p>
              <p className="text-sm text-[#64748B]">{grantGroup.path}</p>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-sm font-medium text-[#374151]">Group Claims</p>
          <p className="text-xs text-[#94A3B8] mb-2">
            This group's permissions are defined in the Groups tab
          </p>
          {grant.claims && grant.claims.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {grant.claims.map(claim => (
                <span
                  key={claim}
                  className="px-2 py-1 text-xs font-medium rounded-full bg-[#F5F3FF] text-[#8950FA]"
                >
                  {CLAIM_LABELS[claim] || claim}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[#64748B] italic">
              Uses group's default claims from Group Access settings
            </p>
          )}
        </div>

        <p className="text-xs text-[#94A3B8]">
          To change which group has access, delete this grant and add a new one.
        </p>

        <div className="flex justify-end pt-2">
          <Button variant="ghost" onClick={onClose} className="gap-2">
            <X className="w-4 h-4" />
            Close
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      {/* Group selection */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Select Group
        </label>
        <p className="text-xs text-[#94A3B8] mb-2">
          Choose which group can access this contract. The group's claims (set in the Groups tab) determine their permissions.
        </p>
        <select
          value={selectedGroupId}
          onChange={e => setSelectedGroupId(e.target.value)}
          className="w-full px-3 py-2 border border-[#E5E7EB] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-[#8950FA] focus:border-transparent"
        >
          <option value="">Select a group...</option>
          {availableGroups.map(group => (
            <option key={group.id} value={group.id}>
              {group.name} ({group.path})
            </option>
          ))}
        </select>
        {availableGroups.length === 0 && (
          <p className="text-xs text-[#DC2626]">
            All groups in this organization already have access to this contract.
          </p>
        )}
      </div>

      {/* Show selected group's info */}
      {selectedGroup && (
        <div className="p-4 rounded-lg bg-[#F5F3FF] border border-[#E9E3FF]">
          <div className="flex items-center gap-3 mb-2">
            <Users className="w-5 h-5 text-[#8950FA]" />
            <p className="font-medium text-[#0F0F0F]">{selectedGroup.name}</p>
          </div>
          <p className="text-xs text-[#64748B]">
            This group's members will have access to this contract based on the group's claim settings.
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
          disabled={saving || !selectedGroupId || availableGroups.length === 0}
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
              Add Group Access
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
