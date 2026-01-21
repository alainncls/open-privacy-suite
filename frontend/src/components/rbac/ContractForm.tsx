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
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!contract;

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
        });
      } else {
        await rbacApi.contracts.create(orgId, {
          contract_address: contractAddress,
          owner_group_id: ownerGroupId,
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
          The group that owns this contract. Members with appropriate role claims can perform actions on it.
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
