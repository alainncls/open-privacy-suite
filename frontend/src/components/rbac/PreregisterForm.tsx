import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, X, Loader2, Calculator, Eye, Rocket } from 'lucide-react';

interface PreregisterFormProps {
  orgId: string;
  onClose: () => void;
  onSave: () => void;
}

// Check if we're in development mode
const isDevelopment = import.meta.env.DEV || import.meta.env.MODE === 'development';

// Simple CREATE3 address preview (for UI purposes only - actual calculation happens server-side)
const generateAddressPreview = (factory: string, saltPrefix: string, count: number): string[] => {
  // This is just for display purposes - generate placeholder addresses
  // The actual addresses are calculated server-side
  const addresses: string[] = [];
  for (let i = 0; i < Math.min(count, 5); i++) {
    // Generate a pseudo-preview based on inputs (not cryptographically accurate)
    const hash = `${factory}${saltPrefix}${i}`.toLowerCase();
    const mockAddr = '0x' + hash.slice(2, 42).padEnd(40, '0');
    addresses.push(mockAddr);
  }
  return addresses;
};

export default function PreregisterForm({
  orgId,
  onClose,
  onSave,
}: PreregisterFormProps) {
  const [factory, setFactory] = useState('');
  const [saltPrefix, setSaltPrefix] = useState('');
  const [count, setCount] = useState(10);
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [previewAddresses, setPreviewAddresses] = useState<string[]>([]);

  // Dev mode state
  const [checkingFactory, setCheckingFactory] = useState(isDevelopment);
  const [deployingFactory, setDeployingFactory] = useState(false);
  const [factoryDeployed, setFactoryDeployed] = useState(false);

  // Check for factory from org config only (per-org isolation - no global factory)
  useEffect(() => {
    if (!orgId) {
      setCheckingFactory(false);
      return;
    }

    const checkFactory = async () => {
      try {
        // Load factory from org config only - each org must have its own factory configured
        const orgConfigResponse = await rbacApi.orgConfig.getCreate3Factory(orgId);
        if (orgConfigResponse.data?.factory && orgConfigResponse.data?.configured) {
          setFactory(orgConfigResponse.data.factory);
          setFactoryDeployed(true);
        }
        // If org doesn't have a factory configured, leave factory empty
        // User must deploy/configure one for this org
      } catch {
        // Org config not available - factory not configured for this org
        console.log('No factory configured for this organization');
      }

      setCheckingFactory(false);
    };

    checkFactory();
  }, [orgId]);

  // Generate preview when inputs change
  useEffect(() => {
    if (factory && factory.match(/^0x[a-fA-F0-9]{40}$/) && saltPrefix && count > 0) {
      setPreviewAddresses(generateAddressPreview(factory, saltPrefix, count));
    } else {
      setPreviewAddresses([]);
    }
  }, [factory, saltPrefix, count]);

  const handleDeployFactory = async () => {
    setDeployingFactory(true);
    setError(null);

    try {
      const response = await rbacApi.dev.deployCreate3Factory();
      const deployedAddress = response.data.address;
      setFactory(deployedAddress);

      // Save the deployed factory to org config for per-org isolation
      try {
        await rbacApi.orgConfig.setCreate3Factory(orgId, deployedAddress);
      } catch (configErr) {
        console.warn('Failed to save factory to org config:', configErr);
        // Continue anyway - the preregister endpoint will save it
      }

      setFactoryDeployed(true);
    } catch (err: unknown) {
      console.error('Failed to deploy CREATE3 factory:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to deploy CREATE3 factory. Please try again.');
      }
    } finally {
      setDeployingFactory(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      await rbacApi.preregisteredAddresses.create(orgId, {
        factory: factory.toLowerCase(),
        salt_prefix: saltPrefix.startsWith('0x') ? saltPrefix : `0x${saltPrefix}`,
        count,
        note: note || undefined,
      });
      onSave();
    } catch (err: unknown) {
      console.error('Failed to preregister addresses:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to preregister addresses. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  const isValidFactory = factory.match(/^0x[a-fA-F0-9]{40}$/);
  const isValidSaltPrefix = saltPrefix.length > 0;
  const isValidCount = count >= 1 && count <= 100;
  const canSubmit = isValidFactory && isValidSaltPrefix && isValidCount;

  // Show loading state while checking for factory
  if (checkingFactory) {
    return (
      <div className="flex flex-col items-center justify-center py-8 space-y-4">
        <Loader2 className="w-8 h-8 animate-spin text-[#8950FA]" />
        <p className="text-sm text-[#6B7280]">Checking CREATE3 factory...</p>
      </div>
    );
  }

  // Show deploy factory dialog in dev mode if not deployed
  if (isDevelopment && !factoryDeployed && !factory) {
    return (
      <div className="space-y-5">
        {error && (
          <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
            <span className="text-[#991B1B] text-sm">{error}</span>
          </div>
        )}

        <div className="p-4 rounded-lg bg-[#FEF3C7] border border-[#FDE68A]">
          <h3 className="font-semibold text-[#92400E] mb-2">Development Mode</h3>
          <p className="text-sm text-[#92400E] mb-4">
            No CREATE3 factory contract is deployed on the local chain.
            Click the button below to deploy one automatically using Anvil's default account.
          </p>
          <Button
            onClick={handleDeployFactory}
            disabled={deployingFactory}
            className="gap-2"
          >
            {deployingFactory ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Deploying Factory...
              </>
            ) : (
              <>
                <Rocket className="w-4 h-4" />
                Deploy CREATE3 Factory
              </>
            )}
          </Button>
        </div>

        <div className="text-center">
          <span className="text-sm text-[#6B7280]">or</span>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium text-[#374151]">
            Use Existing Factory Address
          </label>
          <Input
            type="text"
            value={factory}
            onChange={e => {
              setFactory(e.target.value);
              if (e.target.value.match(/^0x[a-fA-F0-9]{40}$/)) {
                setFactoryDeployed(true);
              }
            }}
            placeholder="0x..."
            pattern="^0x[a-fA-F0-9]{40}$"
            title="Enter a valid Ethereum address"
            className="font-mono"
          />
          <p className="text-xs text-[#94A3B8]">
            If you already have a CREATE3 factory deployed, enter its address here.
          </p>
        </div>

        <div className="flex justify-end pt-2">
          <Button
            type="button"
            variant="ghost"
            onClick={onClose}
            className="gap-2"
          >
            <X className="w-4 h-4" />
            Cancel
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

      {isDevelopment && factoryDeployed && (
        <div className="p-3 rounded-lg bg-[#ECFDF5] border border-[#A7F3D0]">
          <p className="text-sm text-[#065F46]">
            <strong>Dev Mode:</strong> CREATE3 factory deployed at{' '}
            <code className="font-mono text-xs bg-[#D1FAE5] px-1 py-0.5 rounded">{factory}</code>
          </p>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Factory Address
        </label>
        <Input
          type="text"
          value={factory}
          onChange={e => setFactory(e.target.value)}
          placeholder="0x..."
          required
          pattern="^0x[a-fA-F0-9]{40}$"
          title="Enter a valid Ethereum address (0x followed by 40 hex characters)"
          className="font-mono"
          disabled={isDevelopment && factoryDeployed}
        />
        <p className="text-xs text-[#94A3B8]">
          The CREATE3 factory contract address used for deployment
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Salt Prefix
        </label>
        <Input
          type="text"
          value={saltPrefix}
          onChange={e => setSaltPrefix(e.target.value)}
          placeholder="e.g., myapp-v1 or 0xdeadbeef"
          required
        />
        <p className="text-xs text-[#94A3B8]">
          A unique identifier used to derive the salt for each address. Can be hex or text.
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Count
        </label>
        <Input
          type="number"
          value={count}
          onChange={e => setCount(parseInt(e.target.value, 10) || 0)}
          min={1}
          max={100}
          required
          className="w-32"
        />
        <p className="text-xs text-[#94A3B8]">
          Number of addresses to pre-register (1-100)
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Note (optional)
        </label>
        <Input
          type="text"
          value={note}
          onChange={e => setNote(e.target.value)}
          placeholder="e.g., Implementation contracts for v2 upgrade"
        />
        <p className="text-xs text-[#94A3B8]">
          A description to help identify these addresses
        </p>
      </div>

      {/* Preview Section */}
      {canSubmit && (
        <div className="space-y-2">
          <button
            type="button"
            onClick={() => setShowPreview(!showPreview)}
            className="flex items-center gap-2 text-sm text-[#8950FA] hover:text-[#6B3DD4] transition-colors"
          >
            <Eye className="w-4 h-4" />
            {showPreview ? 'Hide' : 'Show'} address preview
          </button>
          {showPreview && previewAddresses.length > 0 && (
            <div className="p-3 rounded-lg bg-[#F1F5F9] border border-[#E2E8F0]">
              <p className="text-xs text-[#6B7280] mb-2">
                Addresses will be generated server-side. This is a preview:
              </p>
              <div className="space-y-1 font-mono text-xs">
                {previewAddresses.map((addr, i) => (
                  <div key={i} className="text-[#374151] truncate">
                    {i + 1}. {addr}
                  </div>
                ))}
                {count > 5 && (
                  <div className="text-[#94A3B8]">
                    ... and {count - 5} more
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="p-3 rounded-lg bg-[#F5F3FF] border border-[#C4A8FD]">
        <p className="text-sm text-[#6B3DD4]">
          <strong>How it works:</strong> CREATE3 addresses are deterministic based on the
          factory and salt. Pre-registering addresses allows you to whitelist future
          deployment targets before the actual bytecode is known.
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
        <Button type="submit" disabled={saving || !canSubmit} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <Calculator className="w-4 h-4" />
              Pre-register {count} Address{count !== 1 ? 'es' : ''}
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
