import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Claim, Group, ContractGrant, CreateContractGrantInput, UpdateContractGrantInput } from '@/types/rbac';
import { ALL_CLAIMS, CLAIM_LABELS, CLAIM_DESCRIPTIONS } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2, Check, Plus, Trash2 } from 'lucide-react';

interface ContractGrantFormProps {
  orgId: string;
  contractAddress: string;
  grant?: ContractGrant | null; // If provided, we're editing
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
  const [selectedClaims, setSelectedClaims] = useState<Claim[]>(grant?.claims || []);
  const [allFunctions, setAllFunctions] = useState<boolean>(!grant?.functions || grant.functions.length === 0);
  const [functions, setFunctions] = useState<string[]>(grant?.functions || []);
  const [newFunction, setNewFunction] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!grant;

  // Available groups (exclude ones that already have grants, unless editing)
  const availableGroups = groups.filter(g =>
    isEditing ? true : !existingGrantGroupIds.includes(g.id)
  );

  const toggleClaim = (claim: Claim) => {
    setSelectedClaims(prev =>
      prev.includes(claim)
        ? prev.filter(c => c !== claim)
        : [...prev, claim]
    );
  };

  const addFunction = () => {
    const trimmed = newFunction.trim().toLowerCase();
    if (!trimmed) return;

    // Validate function selector format (0x followed by 8 hex chars)
    if (!/^0x[a-f0-9]{8}$/.test(trimmed)) {
      setError('Function selector must be 0x followed by 8 hex characters (e.g., 0x70a08231)');
      return;
    }

    if (functions.includes(trimmed)) {
      setError('Function selector already added');
      return;
    }

    setFunctions(prev => [...prev, trimmed]);
    setNewFunction('');
    setError(null);
  };

  const removeFunction = (selector: string) => {
    setFunctions(prev => prev.filter(f => f !== selector));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    if (selectedClaims.length === 0) {
      setError('Please select at least one claim');
      return;
    }

    setSaving(true);

    try {
      if (isEditing) {
        const input: UpdateContractGrantInput = {
          claims: selectedClaims,
          functions: allFunctions ? null : functions.length > 0 ? functions : null,
        };
        await rbacApi.contracts.updateGrant(orgId, contractAddress, grant.group_id, input);
      } else {
        const input: CreateContractGrantInput = {
          group_id: selectedGroupId,
          claims: selectedClaims,
          functions: allFunctions ? null : functions.length > 0 ? functions : null,
        };
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
          Group
        </label>
        <select
          value={selectedGroupId}
          onChange={e => setSelectedGroupId(e.target.value)}
          disabled={isEditing}
          className="w-full px-3 py-2 border border-[#E5E7EB] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-[#8950FA] focus:border-transparent disabled:bg-[#F9FAFB] disabled:cursor-not-allowed"
        >
          <option value="">Select a group...</option>
          {availableGroups.map(group => (
            <option key={group.id} value={group.id}>
              {group.name} ({group.path})
            </option>
          ))}
        </select>
        {isEditing && (
          <p className="text-xs text-[#94A3B8]">
            Group cannot be changed. Delete this grant and create a new one if needed.
          </p>
        )}
      </div>

      {/* Claims selection */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Claims
        </label>
        <p className="text-xs text-[#94A3B8] mb-2">
          Permissions this group has on this contract
        </p>
        <div className="space-y-2">
          {ALL_CLAIMS.map(claim => (
            <label
              key={claim}
              className="flex items-start gap-3 p-2 rounded-lg hover:bg-[#F5F3FF] cursor-pointer"
              onClick={() => toggleClaim(claim)}
            >
              <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
                selectedClaims.includes(claim)
                  ? 'bg-[#8950FA] border-[#8950FA]'
                  : 'border-[#CBD5E1] bg-white'
              }`}>
                {selectedClaims.includes(claim) && <Check className="w-3 h-3 text-white" />}
              </div>
              <div>
                <span className="text-sm font-medium text-[#0F0F0F]">{CLAIM_LABELS[claim]}</span>
                <p className="text-xs text-[#94A3B8]">{CLAIM_DESCRIPTIONS[claim]}</p>
              </div>
            </label>
          ))}
        </div>
      </div>

      {/* Function access */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Function Access
        </label>
        <div className="space-y-3">
          <label
            className="flex items-center gap-3 p-2 rounded-lg hover:bg-[#F5F3FF] cursor-pointer"
            onClick={() => setAllFunctions(true)}
          >
            <div className={`w-5 h-5 rounded-full border flex items-center justify-center flex-shrink-0 transition-colors ${
              allFunctions
                ? 'bg-[#8950FA] border-[#8950FA]'
                : 'border-[#CBD5E1] bg-white'
            }`}>
              {allFunctions && <div className="w-2 h-2 rounded-full bg-white" />}
            </div>
            <div>
              <span className="text-sm font-medium text-[#0F0F0F]">All functions</span>
              <p className="text-xs text-[#94A3B8]">Grant can access any function on this contract</p>
            </div>
          </label>
          <label
            className="flex items-center gap-3 p-2 rounded-lg hover:bg-[#F5F3FF] cursor-pointer"
            onClick={() => setAllFunctions(false)}
          >
            <div className={`w-5 h-5 rounded-full border flex items-center justify-center flex-shrink-0 transition-colors ${
              !allFunctions
                ? 'bg-[#8950FA] border-[#8950FA]'
                : 'border-[#CBD5E1] bg-white'
            }`}>
              {!allFunctions && <div className="w-2 h-2 rounded-full bg-white" />}
            </div>
            <div>
              <span className="text-sm font-medium text-[#0F0F0F]">Specific functions only</span>
              <p className="text-xs text-[#94A3B8]">Restrict to specific function selectors</p>
            </div>
          </label>

          {/* Function selectors list */}
          {!allFunctions && (
            <div className="ml-8 space-y-2">
              {functions.length > 0 && (
                <div className="border rounded-lg divide-y">
                  {functions.map(selector => (
                    <div key={selector} className="flex items-center justify-between px-3 py-2">
                      <span className="font-mono text-sm text-[#374151]">{selector}</span>
                      <button
                        type="button"
                        onClick={() => removeFunction(selector)}
                        className="p-1 rounded hover:bg-[#FEE2E2] text-[#991B1B]"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <div className="flex gap-2">
                <Input
                  value={newFunction}
                  onChange={e => setNewFunction(e.target.value)}
                  placeholder="0x70a08231"
                  className="font-mono"
                  onKeyDown={e => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addFunction();
                    }
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={addFunction}
                >
                  <Plus className="w-4 h-4" />
                </Button>
              </div>
              <p className="text-xs text-[#94A3B8]">
                Enter 4-byte function selectors (e.g., 0x70a08231 for balanceOf)
              </p>
            </div>
          )}
        </div>
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
        <Button type="submit" disabled={saving} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {isEditing ? 'Update Grant' : 'Create Grant'}
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
