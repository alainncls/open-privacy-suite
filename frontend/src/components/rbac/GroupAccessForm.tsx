import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Claim, SetGroupAccessInput } from '@/types/rbac';
import { ALL_CLAIMS, CLAIM_LABELS, CLAIM_DESCRIPTIONS, CLAIM_HIERARCHY, getImplyingClaim, RPC_METHODS_BY_CLAIM } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2, Check, ChevronDown, ChevronRight } from 'lucide-react';

interface GroupAccessFormProps {
  orgId: string;
  groupId: string;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupAccessForm({
  orgId,
  groupId,
  onClose,
  onSave,
}: GroupAccessFormProps) {
  const [loading, setLoading] = useState(true);
  const [allowedMethods, setAllowedMethods] = useState<string[]>([]);
  const [claims, setDefaultClaims] = useState<Claim[]>([]);
  const [rateLimitRPS, setRateLimitRPS] = useState<string>('');
  const [rateLimitDaily, setRateLimitDaily] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    read: true,
    write: true,
  });

  useEffect(() => {
    loadAccess();
  }, [groupId]);

  // When claims change, remove methods that no longer have their required claim
  useEffect(() => {
    const validMethods = allowedMethods.filter(method => {
      if ((RPC_METHODS_BY_CLAIM.read as readonly string[]).includes(method)) {
        return claims.includes('read');
      }
      if ((RPC_METHODS_BY_CLAIM.write as readonly string[]).includes(method)) {
        return claims.includes('write');
      }
      return true; // Unknown methods stay selected
    });

    if (validMethods.length !== allowedMethods.length) {
      setAllowedMethods(validMethods);
    }
  }, [claims]);

  const loadAccess = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.groups.getAccess(orgId, groupId);
      const access = response.data;
      if (access) {
        setAllowedMethods(access.allowed_methods || []);
        setDefaultClaims(access.claims || []);
        setRateLimitRPS(access.rate_limit_rps?.toString() || '');
        setRateLimitDaily(access.rate_limit_daily?.toString() || '');
      }
    } catch {
      // No access settings yet, that's OK
    } finally {
      setLoading(false);
    }
  };

  const toggleMethod = (method: string) => {
    setAllowedMethods(prev =>
      prev.includes(method)
        ? prev.filter(m => m !== method)
        : [...prev, method]
    );
  };

  const toggleClaim = (claim: Claim) => {
    setDefaultClaims(prev => {
      if (prev.includes(claim)) {
        // Unchecking: remove the claim itself
        let next = prev.filter(c => c !== claim);
        // Also uncheck any parent claims that imply this claim
        for (const [parent, implied] of Object.entries(CLAIM_HIERARCHY)) {
          if (implied?.includes(claim) && next.includes(parent as Claim)) {
            next = next.filter(c => c !== parent);
          }
        }
        return next;
      } else {
        // Checking: add the claim and all its implied claims
        const implied = CLAIM_HIERARCHY[claim] || [];
        const set = new Set([...prev, claim, ...implied]);
        return Array.from(set);
      }
    });
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const selectAllInSection = (claimType: 'read' | 'write') => {
    const sectionMethods = RPC_METHODS_BY_CLAIM[claimType];
    setAllowedMethods(prev => {
      const others = prev.filter(m => !(sectionMethods as readonly string[]).includes(m));
      return [...others, ...sectionMethods];
    });
  };

  const clearAllInSection = (claimType: 'read' | 'write') => {
    const sectionMethods = RPC_METHODS_BY_CLAIM[claimType];
    setAllowedMethods(prev =>
      prev.filter(m => !(sectionMethods as readonly string[]).includes(m))
    );
  };

  const getMethodsSelectedCount = (claimType: 'read' | 'write') => {
    const sectionMethods = RPC_METHODS_BY_CLAIM[claimType];
    return allowedMethods.filter(m => (sectionMethods as readonly string[]).includes(m)).length;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const input: SetGroupAccessInput = {
        allowed_methods: allowedMethods,
        claims: claims,
        rate_limit_rps: rateLimitRPS ? parseInt(rateLimitRPS, 10) : null,
        rate_limit_daily: rateLimitDaily ? parseInt(rateLimitDaily, 10) : null,
      };

      await rbacApi.groups.setAccess(orgId, groupId, input);
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save access settings:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save access settings. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-[#94A3B8] animate-spin" />
      </div>
    );
  }

  const renderMethodSection = (claimType: 'read' | 'write', title: string) => {
    const methods = RPC_METHODS_BY_CLAIM[claimType];
    const isExpanded = expandedSections[claimType];
    const hasClaim = claims.includes(claimType);
    const selectedCount = getMethodsSelectedCount(claimType);
    const totalCount = methods.length;

    return (
      <div className={`border rounded-lg ${hasClaim ? 'border-[#E5E7EB]' : 'border-[#F3F4F6] bg-[#F9FAFB]'}`}>
        {/* Section header */}
        <div
          className={`flex items-center justify-between p-3 cursor-pointer ${hasClaim ? 'hover:bg-[#F5F3FF]' : ''}`}
          onClick={() => hasClaim && toggleSection(claimType)}
        >
          <div className="flex items-center gap-2">
            {hasClaim ? (
              isExpanded ? (
                <ChevronDown className="w-4 h-4 text-[#6B7280]" />
              ) : (
                <ChevronRight className="w-4 h-4 text-[#6B7280]" />
              )
            ) : (
              <ChevronRight className="w-4 h-4 text-[#D1D5DB]" />
            )}
            <span className={`text-sm font-medium ${hasClaim ? 'text-[#374151]' : 'text-[#9CA3AF]'}`}>
              {title}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full ${
              hasClaim
                ? 'bg-[#F5F3FF] text-[#8950FA]'
                : 'bg-[#F3F4F6] text-[#9CA3AF]'
            }`}>
              {selectedCount} / {totalCount}
            </span>
          </div>
          {hasClaim && (
            <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
              <button
                type="button"
                className="text-xs text-[#8950FA] hover:text-[#7040E0] font-medium"
                onClick={() => selectAllInSection(claimType)}
              >
                Select All
              </button>
              <span className="text-[#E5E7EB]">|</span>
              <button
                type="button"
                className="text-xs text-[#6B7280] hover:text-[#374151] font-medium"
                onClick={() => clearAllInSection(claimType)}
              >
                Clear
              </button>
            </div>
          )}
        </div>

        {/* Disabled message */}
        {!hasClaim && (
          <div className="px-3 pb-3">
            <p className="text-xs text-[#9CA3AF] italic">
              Enable "{CLAIM_LABELS[claimType]}" claim to configure these methods
            </p>
          </div>
        )}

        {/* Methods grid */}
        {hasClaim && isExpanded && (
          <div className="border-t border-[#E5E7EB] p-2 max-h-48 overflow-y-auto">
            <div className="grid grid-cols-2 gap-1">
              {methods.map(method => (
                <label
                  key={method}
                  className="flex items-center gap-2 p-1.5 rounded hover:bg-[#F5F3FF] cursor-pointer"
                  onClick={() => toggleMethod(method)}
                >
                  <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 transition-colors ${
                    allowedMethods.includes(method)
                      ? 'bg-[#8950FA] border-[#8950FA]'
                      : 'border-[#CBD5E1] bg-white'
                  }`}>
                    {allowedMethods.includes(method) && <Check className="w-2.5 h-2.5 text-white" />}
                  </div>
                  <span className="text-xs font-mono text-[#374151] truncate">{method}</span>
                </label>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      {/* Claims section - moved to top */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Claims
        </label>
        <p className="text-xs text-[#94A3B8] mb-2">
          Capabilities for this group. Apply to unregistered contracts directly, and to registered contracts via grants. Read/Write also control which RPC methods are available.
        </p>
        <div className="space-y-2">
          {ALL_CLAIMS.map(claim => {
            const implyingClaim = getImplyingClaim(claim, claims);
            const isImplied = implyingClaim !== null;
            const isChecked = claims.includes(claim);

            return (
              <label
                key={claim}
                className={`flex items-start gap-3 p-2 rounded-lg ${
                  isImplied ? 'opacity-60 cursor-default' : 'hover:bg-[#F5F3FF] cursor-pointer'
                }`}
                onClick={() => !isImplied && toggleClaim(claim)}
              >
                <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
                  isChecked
                    ? isImplied
                      ? 'bg-[#B8A0F0] border-[#B8A0F0]'
                      : 'bg-[#8950FA] border-[#8950FA]'
                    : 'border-[#CBD5E1] bg-white'
                }`}>
                  {isChecked && <Check className="w-3 h-3 text-white" />}
                </div>
                <div>
                  <span className="text-sm font-medium text-[#0F0F0F]">
                    {CLAIM_LABELS[claim]}
                    {isImplied && (
                      <span className="text-xs font-normal text-[#94A3B8] ml-2">
                        (implied by {CLAIM_LABELS[implyingClaim]})
                      </span>
                    )}
                  </span>
                  <p className="text-xs text-[#94A3B8]">{CLAIM_DESCRIPTIONS[claim]}</p>
                </div>
              </label>
            );
          })}
        </div>
        {claims.length === 0 && (
          <p className="text-xs text-[#EF4444] mt-1">Select at least one claim.</p>
        )}
      </div>

      {/* RPC Methods section - now grouped by claim */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">
          Allowed RPC Methods
        </label>
        <p className="text-xs text-[#94A3B8] mb-2">
          Methods are grouped by required claim. Enable a claim above to configure its methods.
        </p>
        <div className="space-y-2">
          {renderMethodSection('read', 'Read Methods')}
          {renderMethodSection('write', 'Write Methods')}
        </div>
      </div>

      {/* Rate limits */}
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <label className="block text-sm font-medium text-[#374151]">
            Rate Limit (RPS)
          </label>
          <Input
            type="number"
            value={rateLimitRPS}
            onChange={e => setRateLimitRPS(e.target.value)}
            placeholder="100"
            min="0"
          />
          <p className="text-xs text-[#94A3B8]">Requests per second</p>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium text-[#374151]">
            Rate Limit (Daily)
          </label>
          <Input
            type="number"
            value={rateLimitDaily}
            onChange={e => setRateLimitDaily(e.target.value)}
            placeholder="100000"
            min="0"
          />
          <p className="text-xs text-[#94A3B8]">Requests per day</p>
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
        <Button type="submit" disabled={saving || claims.length === 0} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              Save Access Settings
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
