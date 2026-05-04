import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract } from '@/types/rbac';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2, Upload, Check, FileJson, Eye, ShieldAlert } from 'lucide-react';

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

  // ABI upload state
  const [hasAbi, setHasAbi] = useState(!!contract?.abi);
  const [uploadingAbi, setUploadingAbi] = useState(false);
  const [abiSuccess, setAbiSuccess] = useState<string | null>(null);

  // RD-874: visibleTo unlock toggle.
  const [allowVisibleToUnlock, setAllowVisibleToUnlock] = useState(
    !!contract?.allow_visibleto_unlock,
  );
  const [savingUnlock, setSavingUnlock] = useState(false);
  const [unlockSuccess, setUnlockSuccess] = useState<string | null>(null);
  const [pendingUnlockEnable, setPendingUnlockEnable] = useState(false);

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

  // Apply the visibleTo unlock toggle through the dedicated admin endpoint.
  // Caller is expected to have already confirmed when transitioning to true
  // (security-sensitive — see the inline warning + confirmation dialog).
  const applyUnlockToggle = async (allow: boolean) => {
    if (!contract) return;
    setSavingUnlock(true);
    setError(null);
    setUnlockSuccess(null);
    try {
      await rbacApi.contracts.updateAllowVisibleToUnlock(orgId, getContractAddress(contract), allow);
      setAllowVisibleToUnlock(allow);
      setUnlockSuccess(allow ? 'visibleTo unlock enabled for this contract' : 'visibleTo unlock disabled');
    } catch (err: unknown) {
      console.error('Failed to update visibleTo unlock flag:', err);
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to update visibleTo unlock setting.');
    } finally {
      setSavingUnlock(false);
    }
  };

  const handleAbiUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !contract) return;

    setUploadingAbi(true);
    setError(null);
    setAbiSuccess(null);

    try {
      const text = await file.text();
      // Validate JSON
      const parsed = JSON.parse(text);
      if (!Array.isArray(parsed)) {
        throw new Error('ABI must be a JSON array');
      }

      await rbacApi.contracts.updateABI(orgId, getContractAddress(contract), text);
      setHasAbi(true);
      setAbiSuccess(`ABI uploaded successfully (${parsed.length} entries)`);
    } catch (err: unknown) {
      console.error('Failed to upload ABI:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else if (err instanceof SyntaxError) {
        setError('Invalid JSON format in ABI file');
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to upload ABI. Please try again.');
      }
    } finally {
      setUploadingAbi(false);
      // Reset the input so the same file can be selected again
      e.target.value = '';
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
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
        <p className="text-xs text-neutral-400">
          The contract's Ethereum address
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          Name (optional)
        </label>
        <Input
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g., MyToken, Governance Contract"
        />
        <p className="text-xs text-neutral-400">
          A human-readable name for this contract
        </p>
      </div>

      {/* ABI Upload - only show when editing */}
      {isEditing && (
        <div className="space-y-2">
          <label className="block text-sm font-medium text-neutral-700">
            Contract ABI
          </label>
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
              hasAbi
                ? 'bg-success-light border-green-300 text-success-dark'
                : 'bg-neutral-100 border-neutral-200 text-neutral-500'
            }`}>
              {hasAbi ? (
                <>
                  <Check className="w-4 h-4" />
                  <span className="text-sm font-medium">ABI Loaded</span>
                </>
              ) : (
                <>
                  <FileJson className="w-4 h-4" />
                  <span className="text-sm">No ABI</span>
                </>
              )}
            </div>
            <label className="flex items-center gap-2 px-3 py-2 rounded-lg border border-neutral-200 bg-white hover:bg-neutral-100 cursor-pointer transition-colors">
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleAbiUpload}
                className="sr-only"
                disabled={uploadingAbi}
              />
              {uploadingAbi ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-neutral-500" />
                  <span className="text-sm text-neutral-500">Uploading...</span>
                </>
              ) : (
                <>
                  <Upload className="w-4 h-4 text-neutral-500" />
                  <span className="text-sm text-neutral-500">{hasAbi ? 'Replace' : 'Upload'} ABI</span>
                </>
              )}
            </label>
          </div>
          {abiSuccess && (
            <p className="text-xs text-success-dark flex items-center gap-1">
              <Check className="w-3 h-3" />
              {abiSuccess}
            </p>
          )}
          <p className="text-xs text-neutral-400">
            Upload the contract ABI JSON to enable function-level access control
          </p>
        </div>
      )}

      {/* RD-874: per-contract visibleTo unlock toggle. Editing only —
          security-sensitive flag, confirmation required to enable. */}
      {isEditing && (
        <div className="space-y-2">
          <div className="flex items-start justify-between gap-3 p-3 rounded-lg border border-neutral-200">
            <div className="flex items-start gap-3 min-w-0">
              <Eye className="w-5 h-5 mt-0.5 text-neutral-500 flex-shrink-0" />
              <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-neutral-700">
                    visibleTo unlock
                  </span>
                  {allowVisibleToUnlock && (
                    <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-800">
                      enabled
                    </span>
                  )}
                </div>
                <p className="text-xs text-neutral-500">
                  When enabled, a transaction sender on this contract can grant
                  per-event visibility to anyone they list in the tx's <code>visibleTo</code>{' '}
                  array — bypassing the contract grant's event rules and parameter
                  rules for that one transaction. Default off; existing additive
                  behaviour stays.
                </p>
                {allowVisibleToUnlock && (
                  <p className="text-xs text-amber-700 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" />
                    Tx senders on this contract may now share full event payloads
                    with any DID they list.
                  </p>
                )}
                {unlockSuccess && (
                  <p className="text-xs text-success-dark flex items-center gap-1">
                    <Check className="w-3 h-3" />
                    {unlockSuccess}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center">
              {savingUnlock ? (
                <Loader2 className="w-4 h-4 animate-spin text-neutral-500" />
              ) : (
                <input
                  type="checkbox"
                  role="switch"
                  aria-label="Allow visibleTo to unlock event visibility"
                  checked={allowVisibleToUnlock}
                  disabled={savingUnlock}
                  onChange={e => {
                    if (e.target.checked) {
                      // Enabling is security-sensitive — confirm first.
                      setPendingUnlockEnable(true);
                    } else {
                      // Disabling restores the default; safe to do without prompt.
                      void applyUnlockToggle(false);
                    }
                  }}
                  className="w-4 h-4 cursor-pointer"
                />
              )}
            </div>
          </div>
        </div>
      )}

      {pendingUnlockEnable && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-5 space-y-3">
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-6 h-6 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-base font-semibold text-neutral-900">
                  Enable visibleTo unlock?
                </h3>
                <p className="text-sm text-neutral-600 mt-1">
                  Once enabled, any transaction sender on this contract can grant
                  per-event visibility (bypassing event rules and parameter rules)
                  to anyone they list in <code>visibleTo</code> on a transaction.
                  Listed users still need contract-level group access in this org —
                  cross-org and anonymous viewers remain denied.
                </p>
                <p className="text-sm text-neutral-600 mt-2">
                  Set this only on contracts where shared per-tx visibility is the
                  intended workflow.
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setPendingUnlockEnable(false)}
                disabled={savingUnlock}
              >
                Cancel
              </Button>
              <Button
                type="button"
                onClick={async () => {
                  setPendingUnlockEnable(false);
                  await applyUnlockToggle(true);
                }}
                disabled={savingUnlock}
                className="gap-2"
              >
                {savingUnlock ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                Enable
              </Button>
            </div>
          </div>
        </div>
      )}

      <div className="p-3 rounded-lg bg-primary-50 border border-primary-200">
        <p className="text-sm text-primary-600">
          <strong>Tip:</strong> After registering the contract, add grants to specify
          which groups can access it and with what claims (admin, deploy, upgrade).
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
