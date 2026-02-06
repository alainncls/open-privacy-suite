import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, ContractGrant, CreateContractGrantInput } from '@/types/rbac';
import { CLAIM_LABELS } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { AlertCircle, Save, X, Loader2, Users, Plus, Trash2 } from 'lucide-react';

interface ContractGrantFormProps {
  orgId: string;
  contractAddress: string;
  grant?: ContractGrant | null; // If provided, we're editing
  groups: Group[];
  existingGrantGroupIds: string[]; // Groups that already have grants (for filtering)
  onClose: () => void;
  onSave: () => void;
}

// Common function selectors with human-readable names
const COMMON_SELECTORS: Record<string, string> = {
  '0x70a08231': 'balanceOf(address)',
  '0x18160ddd': 'totalSupply()',
  '0xa9059cbb': 'transfer(address,uint256)',
  '0x23b872dd': 'transferFrom(address,address,uint256)',
  '0x095ea7b3': 'approve(address,uint256)',
  '0xdd62ed3e': 'allowance(address,address)',
  '0x06fdde03': 'name()',
  '0x95d89b41': 'symbol()',
  '0x313ce567': 'decimals()',
};

// Validate function selector format (0x + 8 hex chars)
const isValidSelector = (selector: string): boolean => {
  return /^0x[a-fA-F0-9]{8}$/.test(selector);
};

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
  const [functionMode, setFunctionMode] = useState<'all' | 'specific'>(
    grant?.functions && grant.functions.length > 0 ? 'specific' : 'all'
  );
  const [functions, setFunctions] = useState<string[]>(grant?.functions || []);
  const [newSelector, setNewSelector] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!grant;

  // Available groups (exclude ones that already have grants, except current grant's group)
  const availableGroups = groups.filter(
    g => !existingGrantGroupIds.includes(g.id) || g.id === grant?.group_id
  );

  // Get the selected group's details to show its claims
  const selectedGroup = groups.find(g => g.id === selectedGroupId);
  const grantGroup = grant ? groups.find(g => g.id === grant.group_id) : null;

  const handleAddSelector = () => {
    const selector = newSelector.trim().toLowerCase();
    if (!selector) return;

    if (!isValidSelector(selector)) {
      setError('Invalid selector format. Must be 0x followed by 8 hex characters (e.g., 0x70a08231)');
      return;
    }

    if (functions.includes(selector)) {
      setError('This selector is already added');
      return;
    }

    setFunctions([...functions, selector]);
    setNewSelector('');
    setError(null);
  };

  const handleRemoveSelector = (selector: string) => {
    setFunctions(functions.filter(f => f !== selector));
  };

  const handleAddCommonSelector = (selector: string) => {
    if (!functions.includes(selector)) {
      setFunctions([...functions, selector]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    if (functionMode === 'specific' && functions.length === 0) {
      setError('Please add at least one function selector, or select "All functions"');
      return;
    }

    setSaving(true);

    try {
      const input: CreateContractGrantInput = {
        group_id: selectedGroupId,
        claims: [], // Use group's default claims
        functions: functionMode === 'all' ? null : functions,
      };

      if (isEditing) {
        // Update existing grant
        await rbacApi.contracts.updateGrant(orgId, contractAddress, grant.group_id, {
          functions: functionMode === 'all' ? null : functions,
        });
      } else {
        // Create new grant
        await rbacApi.contracts.createGrant(orgId, contractAddress, input);
      }
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

  // Get selector label (name if known, otherwise just the selector)
  const getSelectorLabel = (selector: string) => {
    return COMMON_SELECTORS[selector] || selector;
  };

  // If viewing an existing grant in read-only mode (old UI behavior kept for reference)
  if (isEditing && grantGroup && false) { // Disabled - we now support editing
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
          disabled={isEditing} // Can't change group when editing
          className="w-full px-3 py-2 border border-[#E5E7EB] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-[#8950FA] focus:border-transparent disabled:bg-[#F9FAFB] disabled:text-[#6B7280]"
        >
          <option value="">Select a group...</option>
          {availableGroups.map(group => (
            <option key={group.id} value={group.id}>
              {group.name} ({group.path})
            </option>
          ))}
        </select>
        {!isEditing && availableGroups.length === 0 && (
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

      {/* Function Access */}
      <div className="space-y-3">
        <label className="block text-sm font-medium text-[#374151]">
          Function Access
        </label>
        <p className="text-xs text-[#94A3B8]">
          Restrict access to specific contract functions, or allow all functions.
        </p>

        {/* Radio options */}
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 border border-[#E5E7EB] rounded-lg cursor-pointer hover:bg-[#F9FAFB] transition-colors">
            <input
              type="radio"
              name="functionMode"
              value="all"
              checked={functionMode === 'all'}
              onChange={() => setFunctionMode('all')}
              className="w-4 h-4 text-[#8950FA] focus:ring-[#8950FA]"
            />
            <div>
              <p className="text-sm font-medium text-[#0F0F0F]">All functions</p>
              <p className="text-xs text-[#6B7280]">Group can call any function on this contract</p>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 border border-[#E5E7EB] rounded-lg cursor-pointer hover:bg-[#F9FAFB] transition-colors">
            <input
              type="radio"
              name="functionMode"
              value="specific"
              checked={functionMode === 'specific'}
              onChange={() => setFunctionMode('specific')}
              className="w-4 h-4 text-[#8950FA] focus:ring-[#8950FA]"
            />
            <div>
              <p className="text-sm font-medium text-[#0F0F0F]">Specific functions only</p>
              <p className="text-xs text-[#6B7280]">Restrict to selected function selectors</p>
            </div>
          </label>
        </div>

        {/* Function selector input (shown when specific mode) */}
        {functionMode === 'specific' && (
          <div className="space-y-3 pt-2">
            {/* Current selectors */}
            {functions.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-[#6B7280]">Allowed functions:</p>
                <div className="flex flex-wrap gap-2">
                  {functions.map(selector => (
                    <span
                      key={selector}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[#F5F3FF] text-[#8950FA] border border-[#E9E3FF]"
                    >
                      <code className="font-mono">{selector}</code>
                      {COMMON_SELECTORS[selector] && (
                        <span className="text-[#A78BFA]">({COMMON_SELECTORS[selector]})</span>
                      )}
                      <button
                        type="button"
                        onClick={() => handleRemoveSelector(selector)}
                        className="ml-1 hover:text-[#7C3AED]"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Add new selector */}
            <div className="flex gap-2">
              <input
                type="text"
                value={newSelector}
                onChange={e => setNewSelector(e.target.value)}
                placeholder="0x70a08231"
                className="flex-1 px-3 py-2 border border-[#E5E7EB] rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#8950FA] focus:border-transparent"
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddSelector();
                  }
                }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleAddSelector}
                className="gap-1"
              >
                <Plus className="w-4 h-4" />
                Add
              </Button>
            </div>

            {/* Common selectors */}
            <div className="space-y-2">
              <p className="text-xs font-medium text-[#6B7280]">Common selectors:</p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(COMMON_SELECTORS).map(([selector, name]) => (
                  <button
                    key={selector}
                    type="button"
                    onClick={() => handleAddCommonSelector(selector)}
                    disabled={functions.includes(selector)}
                    className="px-2 py-1 text-xs rounded border border-[#E5E7EB] hover:bg-[#F9FAFB] hover:border-[#DDD6FE] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <code className="font-mono text-[#6B7280]">{selector}</code>
                    <span className="ml-1 text-[#94A3B8]">{name}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

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
          disabled={saving || !selectedGroupId || (!isEditing && availableGroups.length === 0)}
          className="gap-2"
        >
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              {isEditing ? 'Saving...' : 'Adding...'}
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {isEditing ? 'Save Changes' : 'Add Group Access'}
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
