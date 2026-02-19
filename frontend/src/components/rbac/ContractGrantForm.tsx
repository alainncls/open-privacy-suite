import { useState, useMemo } from 'react';
import { toFunctionSelector } from 'viem';
import { rbacApi } from '@/api/rbac';
import type { Group, ContractGrant, CreateContractGrantInput, FunctionRule, ParamRule } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { AlertCircle, Save, X, Loader2, Users, Plus, FileJson } from 'lucide-react';

interface ContractGrantFormProps {
  orgId: string;
  contractAddress: string;
  contractAbi?: string; // Contract ABI JSON string
  grant?: ContractGrant | null; // If provided, we're editing
  groups: Group[];
  existingGrantGroupIds: string[]; // Groups that already have grants (for filtering)
  onClose: () => void;
  onSave: () => void;
}

// Parsed ABI function entry
interface AbiFunctionInput {
  index: number;
  name: string;
  type: string;
}

interface AbiFunction {
  selector: string;
  name: string;
  signature: string;
  stateMutability?: string;
  inputs: AbiFunctionInput[];
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

// Known parameter info for common selectors (used when ABI is not available)
const COMMON_SELECTOR_PARAMS: Record<string, AbiFunctionInput[]> = {
  '0x70a08231': [{ index: 0, name: 'account', type: 'address' }],
  '0xa9059cbb': [{ index: 0, name: 'to', type: 'address' }],
  '0x23b872dd': [
    { index: 0, name: 'from', type: 'address' },
    { index: 1, name: 'to', type: 'address' },
  ],
  '0x095ea7b3': [{ index: 0, name: 'spender', type: 'address' }],
  '0xdd62ed3e': [
    { index: 0, name: 'owner', type: 'address' },
    { index: 1, name: 'spender', type: 'address' },
  ],
};

// Validate function selector format (0x + 8 hex chars)
const isValidSelector = (selector: string): boolean => {
  return /^0x[a-fA-F0-9]{8}$/.test(selector);
};

export default function ContractGrantForm({
  orgId,
  contractAddress,
  contractAbi,
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
  const [functions, setFunctions] = useState<FunctionRule[]>(grant?.functions || []);
  const [newSelector, setNewSelector] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!grant;

  // Parse ABI to extract function selectors
  const abiFunctions = useMemo<AbiFunction[]>(() => {
    if (!contractAbi) return [];
    try {
      const parsed = JSON.parse(contractAbi);
      if (!Array.isArray(parsed)) return [];

      const results: AbiFunction[] = [];
      for (const item of parsed) {
        if (item.type !== 'function') continue;
        const abiInputs = item.inputs || [];
        const inputTypes = abiInputs.map((input: { type: string }) => input.type).join(',');
        const signature = `${item.name}(${inputTypes})`;
        try {
          const selector = toFunctionSelector(signature);
          results.push({
            selector,
            name: item.name,
            signature,
            stateMutability: item.stateMutability,
            inputs: abiInputs.map((input: { name: string; type: string }, idx: number) => ({
              index: idx,
              name: input.name,
              type: input.type,
            })),
          });
        } catch {
          // Skip invalid signatures
        }
      }
      return results;
    } catch {
      return [];
    }
  }, [contractAbi]);

  // Available groups (exclude ones that already have grants, except current grant's group)
  const availableGroups = groups.filter(
    g => !existingGrantGroupIds.includes(g.id) || g.id === grant?.group_id
  );

  // Get the selected group's details to show its claims
  const selectedGroup = groups.find(g => g.id === selectedGroupId);

  // Helper to check if a selector is already in the functions list
  const hasFunctionSelector = (selector: string): boolean => {
    return functions.some(f => f.selector.toLowerCase() === selector.toLowerCase());
  };

  const handleAddSelector = () => {
    const selector = newSelector.trim().toLowerCase();
    if (!selector) return;

    if (!isValidSelector(selector)) {
      setError('Invalid selector format. Must be 0x followed by 8 hex characters (e.g., 0x70a08231)');
      return;
    }

    if (hasFunctionSelector(selector)) {
      setError('This selector is already added');
      return;
    }

    setFunctions([...functions, { selector }]);
    setNewSelector('');
    setError(null);
  };

  const handleRemoveSelector = (selector: string) => {
    setFunctions(functions.filter(f => f.selector.toLowerCase() !== selector.toLowerCase()));
  };

  const handleAddCommonSelector = (selector: string) => {
    if (!hasFunctionSelector(selector)) {
      setFunctions([...functions, { selector }]);
    }
  };

  // Toggle a param_rule on a function rule
  const handleToggleParamRule = (selector: string, paramIndex: number, checked: boolean) => {
    setFunctions(prev =>
      prev.map(rule => {
        if (rule.selector.toLowerCase() !== selector.toLowerCase()) return rule;
        const existing = rule.param_rules || [];
        if (checked) {
          // Add the param rule if not already present
          if (existing.some(pr => pr.index === paramIndex)) return rule;
          const newRule: ParamRule = { index: paramIndex, must_be: 'self' };
          return { ...rule, param_rules: [...existing, newRule] };
        } else {
          // Remove the param rule
          const filtered = existing.filter(pr => pr.index !== paramIndex);
          return { ...rule, param_rules: filtered.length > 0 ? filtered : null };
        }
      })
    );
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
        // claims field is deprecated - permissions come from the group's GroupAccess.claims
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

  // Get selector label (from ABI if available, then common selectors, then just the selector)
  const getSelectorLabel = (selector: string) => {
    // First check ABI functions
    const abiFunc = abiFunctions.find(f => f.selector.toLowerCase() === selector.toLowerCase());
    if (abiFunc) return abiFunc.signature;
    // Then check common selectors
    return COMMON_SELECTORS[selector] || selector;
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
            {/* Warning when no ABI is available */}
            {!contractAbi && (
              <div className="p-4 rounded-lg bg-[#FEF9C3] border border-[#FDE68A] flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-[#92400E] flex-shrink-0 mt-0.5" />
                <span className="text-[#92400E] text-sm">
                  No ABI uploaded for this contract. Function names shown are based on common ERC20 selectors and may not match this contract's actual interface.
                </span>
              </div>
            )}
            {/* Current selectors */}
            {functions.length > 0 && (
              <div className="space-y-3">
                <p className="text-xs font-medium text-[#6B7280]">Allowed functions:</p>
                <div className="space-y-2">
                  {functions.map(rule => {
                    const label = getSelectorLabel(rule.selector);
                    const hasLabel = label !== rule.selector;
                    // Find ABI info for this function to show address-param checkboxes
                    const abiFunc = abiFunctions.find(
                      f => f.selector.toLowerCase() === rule.selector.toLowerCase()
                    );
                    const addressParams = abiFunc
                      ? abiFunc.inputs.filter(inp => inp.type === 'address')
                      : (COMMON_SELECTOR_PARAMS[rule.selector.toLowerCase()] || []);

                    return (
                      <div
                        key={rule.selector}
                        className="p-2 rounded-lg border border-[#E9E3FF] bg-[#FAFAFF]"
                      >
                        <div className="flex items-center gap-1.5">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[#F5F3FF] text-[#8950FA] border border-[#E9E3FF]">
                            <code className="font-mono">{rule.selector}</code>
                            {hasLabel && (
                              <span className="text-[#A78BFA]">({label})</span>
                            )}
                          </span>
                          {(rule.param_rules || []).map(pr => (
                            <span
                              key={pr.index}
                              className="px-1.5 py-0.5 rounded text-[10px] bg-[#FEF3C7] text-[#92400E] border border-[#FDE68A] font-medium"
                            >
                              param[{pr.index}]={pr.must_be}
                            </span>
                          ))}
                          <button
                            type="button"
                            onClick={() => handleRemoveSelector(rule.selector)}
                            className="ml-auto hover:text-[#7C3AED] text-[#A78BFA]"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                        {/* Parameter constraints for address-type params */}
                        {addressParams.length > 0 && (
                          <div className="mt-2 ml-2 space-y-1">
                            {addressParams.map(param => {
                              const isChecked = (rule.param_rules || []).some(
                                pr => pr.index === param.index && pr.must_be === 'self'
                              );
                              return (
                                <label
                                  key={param.index}
                                  className="flex items-center gap-2 text-xs text-[#6B7280] cursor-pointer"
                                >
                                  <input
                                    type="checkbox"
                                    checked={isChecked}
                                    onChange={e =>
                                      handleToggleParamRule(rule.selector, param.index, e.target.checked)
                                    }
                                    className="w-3.5 h-3.5 rounded text-[#8950FA] focus:ring-[#8950FA]"
                                  />
                                  <span>
                                    <code className="font-mono text-[#374151]">{param.name || `param[${param.index}]`}</code>
                                    {' '}must be caller's own address
                                  </span>
                                </label>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
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

            {/* ABI Functions (if available) or Common selectors */}
            {abiFunctions.length > 0 ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <FileJson className="w-3.5 h-3.5 text-[#22C55E]" />
                  <p className="text-xs font-medium text-[#166534]">Contract functions ({abiFunctions.length}):</p>
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1 border border-[#E5E7EB] rounded-lg p-2">
                  {abiFunctions.map(({ selector, name, stateMutability }) => {
                    const isView = stateMutability === 'view' || stateMutability === 'pure';
                    return (
                      <button
                        key={selector}
                        type="button"
                        onClick={() => handleAddCommonSelector(selector)}
                        disabled={hasFunctionSelector(selector)}
                        className="w-full flex items-center justify-between px-2 py-1.5 text-xs rounded hover:bg-[#F9FAFB] hover:border-[#DDD6FE] disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-left"
                      >
                        <span className="flex items-center gap-2 min-w-0">
                          <code className="font-mono text-[#6B7280] truncate">{name}</code>
                          {isView && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-[#DCFCE7] text-[#166534] font-medium">
                              view
                            </span>
                          )}
                        </span>
                        <code className="font-mono text-[#94A3B8] text-[10px] ml-2 flex-shrink-0">{selector}</code>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-xs font-medium text-[#6B7280]">Common selectors:</p>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(COMMON_SELECTORS).map(([selector, name]) => (
                    <button
                      key={selector}
                      type="button"
                      onClick={() => handleAddCommonSelector(selector)}
                      disabled={hasFunctionSelector(selector)}
                      className="px-2 py-1 text-xs rounded border border-[#E5E7EB] hover:bg-[#F9FAFB] hover:border-[#DDD6FE] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <code className="font-mono text-[#6B7280]">{selector}</code>
                      <span className="ml-1 text-[#94A3B8]">{name}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
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
