import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract, PreregisteredAddress } from '@/types/rbac';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2, ChevronDown, MapPin, Upload, Check, FileJson } from 'lucide-react';

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

  // Pre-registered addresses state
  const [preregisteredAddresses, setPreregisteredAddresses] = useState<PreregisteredAddress[]>([]);
  const [registeredContracts, setRegisteredContracts] = useState<Contract[]>([]);
  const [loadingPreregistered, setLoadingPreregistered] = useState(true);
  const [showSuggestions, setShowSuggestions] = useState(false);

  const isEditing = !!contract;

  // Load pre-registered addresses and registered contracts
  useEffect(() => {
    if (isEditing) {
      setLoadingPreregistered(false);
      return;
    }

    const loadData = async () => {
      try {
        const [preregResponse, contractsResponse] = await Promise.all([
          rbacApi.preregisteredAddresses.list(orgId),
          rbacApi.contracts.list(orgId),
        ]);
        setPreregisteredAddresses(preregResponse.data || []);
        setRegisteredContracts(contractsResponse.data || []);
      } catch (err) {
        console.error('Failed to load pre-registered addresses:', err);
      } finally {
        setLoadingPreregistered(false);
      }
    };

    loadData();
  }, [orgId, isEditing]);

  // Filter available pre-registered addresses (not yet registered as contracts)
  const availablePreregistered = preregisteredAddresses.filter(prereg => {
    const preregAddr = prereg.address.toLowerCase();
    return !registeredContracts.some(
      c => (c.address || c.contract_address || '').toLowerCase() === preregAddr
    );
  });

  const handleSelectPreregistered = (prereg: PreregisteredAddress) => {
    setAddress(prereg.address);
    if (prereg.note && !name) {
      // Auto-fill name from note if available
      setName(prereg.note);
    }
    setShowSuggestions(false);
  };

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
        <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Contract Address
        </label>
        <div className="relative">
          <Input
            type="text"
            value={address}
            onChange={e => setAddress(e.target.value)}
            placeholder="0x..."
            required
            disabled={isEditing}
            pattern="^0x[a-fA-F0-9]{40}$"
            title="Enter a valid Ethereum address (0x followed by 40 hex characters)"
            className="font-mono pr-10"
          />
          {!isEditing && availablePreregistered.length > 0 && (
            <button
              type="button"
              onClick={() => setShowSuggestions(!showSuggestions)}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-[#6B7280] hover:text-[#374151] transition-colors"
              title="Select from pre-registered addresses"
            >
              <ChevronDown className={`w-4 h-4 transition-transform ${showSuggestions ? 'rotate-180' : ''}`} />
            </button>
          )}
        </div>

        {/* Pre-registered addresses dropdown */}
        {showSuggestions && availablePreregistered.length > 0 && (
          <div className="mt-1 border border-[#E2E8F0] rounded-lg bg-white shadow-lg max-h-48 overflow-y-auto">
            <div className="px-3 py-2 bg-[#F8FAFC] border-b border-[#E2E8F0]">
              <p className="text-xs font-medium text-[#6B7280] flex items-center gap-1">
                <MapPin className="w-3 h-3" />
                Pre-registered Addresses ({availablePreregistered.length} available)
              </p>
            </div>
            {availablePreregistered.map((prereg) => (
              <button
                key={prereg.id}
                type="button"
                onClick={() => handleSelectPreregistered(prereg)}
                className="w-full px-3 py-2 text-left hover:bg-[#F1F5F9] transition-colors border-b border-[#E2E8F0] last:border-b-0"
              >
                <div className="font-mono text-sm text-[#374151] truncate">
                  {prereg.address}
                </div>
                {prereg.note && (
                  <div className="text-xs text-[#6B7280] truncate mt-0.5">
                    {prereg.note}
                  </div>
                )}
              </button>
            ))}
          </div>
        )}

        <p className="text-xs text-[#94A3B8]">
          The contract's Ethereum address
          {!isEditing && availablePreregistered.length > 0 && (
            <span className="text-[#8950FA]"> • {availablePreregistered.length} pre-registered addresses available</span>
          )}
        </p>
      </div>

      {/* Show hint about pre-registered addresses */}
      {!isEditing && !loadingPreregistered && availablePreregistered.length > 0 && !address && (
        <div className="p-3 rounded-lg bg-[#F0F9FF] border border-[#BAE6FD]">
          <p className="text-sm text-[#0369A1]">
            <strong>Tip:</strong> You have {availablePreregistered.length} pre-registered CREATE3
            {availablePreregistered.length === 1 ? ' address' : ' addresses'} available.
            Click the dropdown arrow to select one.
          </p>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Name (optional)
        </label>
        <Input
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g., MyToken, Governance Contract"
        />
        <p className="text-xs text-[#94A3B8]">
          A human-readable name for this contract
        </p>
      </div>

      {/* ABI Upload - only show when editing */}
      {isEditing && (
        <div className="space-y-2">
          <label className="block text-sm font-medium text-[#374151]">
            Contract ABI
          </label>
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
              hasAbi
                ? 'bg-[#DCFCE7] border-[#86EFAC] text-[#166534]'
                : 'bg-[#F1F5F9] border-[#E2E8F0] text-[#6B7280]'
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
            <label className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#E2E8F0] bg-white hover:bg-[#F8FAFC] cursor-pointer transition-colors">
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleAbiUpload}
                className="sr-only"
                disabled={uploadingAbi}
              />
              {uploadingAbi ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-[#6B7280]" />
                  <span className="text-sm text-[#6B7280]">Uploading...</span>
                </>
              ) : (
                <>
                  <Upload className="w-4 h-4 text-[#6B7280]" />
                  <span className="text-sm text-[#6B7280]">{hasAbi ? 'Replace' : 'Upload'} ABI</span>
                </>
              )}
            </label>
          </div>
          {abiSuccess && (
            <p className="text-xs text-[#166534] flex items-center gap-1">
              <Check className="w-3 h-3" />
              {abiSuccess}
            </p>
          )}
          <p className="text-xs text-[#94A3B8]">
            Upload the contract ABI JSON to enable function-level access control
          </p>
        </div>
      )}

      <div className="p-3 rounded-lg bg-[#F5F3FF] border border-[#C4A8FD]">
        <p className="text-sm text-[#6B3DD4]">
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
