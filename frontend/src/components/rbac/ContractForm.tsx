import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract } from '@/types/rbac';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2 } from 'lucide-react';

interface ContractFormProps {
  orgId: string;
  contract?: Contract;
  onClose: () => void;
  onSave: () => void;
}

export default function ContractForm({
  orgId,
  contract,
  onClose,
  onSave,
}: ContractFormProps) {
  const [address, setAddress] = useState(contract ? getContractAddress(contract) : '');
  const [name, setName] = useState(contract?.name || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!contract;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      if (isEditing) {
        await rbacApi.contracts.update(orgId, getContractAddress(contract), {
          name: name || undefined,
        });
      } else {
        await rbacApi.contracts.create(orgId, {
          address: address.toLowerCase(),
          name: name || undefined,
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
          value={address}
          onChange={e => setAddress(e.target.value)}
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
        <label className="block text-sm font-medium text-white/70">
          Name (optional)
        </label>
        <Input
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g., MyToken, Governance Contract"
        />
        <p className="text-xs text-white/40">
          A human-readable name for this contract
        </p>
      </div>

      <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
        <p className="text-sm text-blue-400">
          <strong>Tip:</strong> After registering the contract, add grants to specify
          which groups can access it and with what claims (read, write, admin, upgrade).
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
        <Button type="submit" disabled={saving} className="gap-2">
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
