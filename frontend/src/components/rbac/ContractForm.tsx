import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { ContractOwnership, Group } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertCircle, Save, X, Loader2, FolderTree } from 'lucide-react';

const COMMON_ABILITIES = ['upgrade', 'pause', 'admin', 'mint', 'burn', 'transfer'];

interface ContractFormProps {
  orgId: string;
  groups: Group[];
  contract?: ContractOwnership;
  onClose: () => void;
  onSave: () => void;
}

export default function ContractForm({
  orgId,
  groups,
  contract,
  onClose,
  onSave,
}: ContractFormProps) {
  const [contractAddress, setContractAddress] = useState(contract?.contract_address || '');
  const [ownerGroupId, setOwnerGroupId] = useState(contract?.owner_group_id || '');
  const [abilities, setAbilities] = useState<string[]>(contract?.owner_abilities || []);
  const [customAbility, setCustomAbility] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!contract;

  const toggleAbility = (ability: string) => {
    if (abilities.includes(ability)) {
      setAbilities(abilities.filter(a => a !== ability));
    } else {
      setAbilities([...abilities, ability]);
    }
  };

  const addCustomAbility = () => {
    if (customAbility && !abilities.includes(customAbility)) {
      setAbilities([...abilities, customAbility]);
      setCustomAbility('');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!ownerGroupId) {
      setError('Please select an owner group');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      if (isEditing) {
        await rbacApi.contracts.update(orgId, contract.contract_address, {
          owner_group_id: ownerGroupId,
          owner_abilities: abilities,
        });
      } else {
        await rbacApi.contracts.create(orgId, {
          contract_address: contractAddress,
          owner_group_id: ownerGroupId,
          owner_abilities: abilities,
        });
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save contract:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save contract. Please try again.');
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
        <label className="block text-sm font-medium text-white/70">
          Contract Address
        </label>
        <Input
          type="text"
          value={contractAddress}
          onChange={e => setContractAddress(e.target.value)}
          placeholder="0x..."
          required
          disabled={isEditing}
          pattern="^0x[a-fA-F0-9]{40}$"
          title="Enter a valid Ethereum address (0x followed by 40 hex characters)"
          className="font-mono"
        />
        <p className="text-xs text-white/40">
          The contract's Ethereum address
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">Owner Group</label>
        {groups.length === 0 ? (
          <p className="text-white/40 text-sm py-2">
            No groups available. Create a group first.
          </p>
        ) : (
          <Select value={ownerGroupId} onValueChange={setOwnerGroupId}>
            <SelectTrigger>
              <SelectValue placeholder="Select owner group" />
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
        <p className="text-xs text-white/40">
          The group that owns this contract
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Owner Abilities
        </label>
        <div className="flex flex-wrap gap-2">
          {COMMON_ABILITIES.map(ability => (
            <button
              key={ability}
              type="button"
              onClick={() => toggleAbility(ability)}
              className={`px-3 py-1.5 rounded-lg border text-sm transition-all ${
                abilities.includes(ability)
                  ? 'border-primary-500/50 bg-primary-500/20 text-primary-400'
                  : 'border-white/20 bg-white/5 text-white/60 hover:border-white/30 hover:bg-white/10'
              }`}
            >
              {ability}
            </button>
          ))}
        </div>

        {/* Custom abilities */}
        {abilities
          .filter(a => !COMMON_ABILITIES.includes(a))
          .map(ability => (
            <div key={ability} className="flex items-center gap-2 mt-2">
              <span className="px-3 py-1.5 rounded-lg border border-primary-500/50 bg-primary-500/20 text-primary-400 text-sm">
                {ability}
              </span>
              <button
                type="button"
                onClick={() => setAbilities(abilities.filter(a => a !== ability))}
                className="text-white/40 hover:text-red-400"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}

        {/* Add custom ability */}
        <div className="flex gap-2 mt-2">
          <Input
            type="text"
            value={customAbility}
            onChange={e => setCustomAbility(e.target.value)}
            placeholder="Custom ability..."
            className="flex-1"
            onKeyDown={e => {
              if (e.key === 'Enter') {
                e.preventDefault();
                addCustomAbility();
              }
            }}
          />
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={addCustomAbility}
            disabled={!customAbility}
          >
            Add
          </Button>
        </div>
        <p className="text-xs text-white/40">
          Abilities the owner group has on this contract
        </p>
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
        <Button type="submit" disabled={saving || !ownerGroupId} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {isEditing ? 'Update' : 'Register'} Contract
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
