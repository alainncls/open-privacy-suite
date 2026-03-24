import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Claim, SetGroupAccessInput } from '@/types/rbac';
import { ALL_CLAIMS, CLAIM_LABELS, CLAIM_DESCRIPTIONS, CLAIM_HIERARCHY, getImplyingClaim, RPC_METHODS_BY_CLAIM, METHOD_CATEGORIES } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2, Check, ChevronDown, ChevronRight, Info, AlertTriangle } from 'lucide-react';

interface GroupAccessFormProps {
  orgId: string;
  groupId: string;
  parentGroup?: { name: string; claims: Claim[] } | null;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupAccessForm({
  orgId,
  groupId,
  parentGroup,
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
  const [expandedSections, setExpandedSections] = useState<{ [key in 'read' | 'write' | 'deploy']: boolean }>({
    read: true,
    write: true,
    deploy: false,
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
      if ((RPC_METHODS_BY_CLAIM.deploy as readonly string[]).includes(method)) {
        return claims.includes('deploy');
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
        // Unchecking: remove the claim and all claims that were only there
        // because of the hierarchy. Also remove parent claims that imply this one.
        let toRemove = new Set<Claim>([claim]);

        // Remove any parent claims that imply this claim
        for (const [parent, implied] of Object.entries(CLAIM_HIERARCHY)) {
          if (implied?.includes(claim)) {
            toRemove.add(parent as Claim);
          }
        }

        // Remove implied children, cascading: a child is removed if every
        // parent that implies it is being removed
        let changed = true;
        while (changed) {
          changed = false;
          for (const removed of toRemove) {
            for (const child of (CLAIM_HIERARCHY[removed] || [])) {
              if (toRemove.has(child)) continue;
              const stillImplied = prev.some(c =>
                !toRemove.has(c) && (CLAIM_HIERARCHY[c]?.includes(child) ?? false)
              );
              if (!stillImplied) {
                toRemove.add(child);
                changed = true;
              }
            }
          }
        }

        return prev.filter(c => !toRemove.has(c));
      } else {
        // Checking: add the claim and all its implied claims
        const implied = CLAIM_HIERARCHY[claim] || [];
        const set = new Set([...prev, claim, ...implied]);
        return Array.from(set);
      }
    });
  };

  const toggleSection = (section: 'read' | 'write' | 'deploy') => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const selectAllInSection = (claimType: 'read' | 'write' | 'deploy') => {
    const sectionMethods = RPC_METHODS_BY_CLAIM[claimType];
    setAllowedMethods(prev => {
      const others = prev.filter(m => !(sectionMethods as readonly string[]).includes(m));
      return [...others, ...sectionMethods];
    });
  };

  const clearAllInSection = (claimType: 'read' | 'write' | 'deploy') => {
    const sectionMethods = RPC_METHODS_BY_CLAIM[claimType];
    setAllowedMethods(prev =>
      prev.filter(m => !(sectionMethods as readonly string[]).includes(m))
    );
  };

  const getMethodsSelectedCount = (claimType: 'read' | 'write' | 'deploy') => {
    const sectionMethods = RPC_METHODS_BY_CLAIM[claimType];
    return allowedMethods.filter(m => (sectionMethods as readonly string[]).includes(m)).length;
  };

  // Claims with no methods selected are useless — the claim grants capability
  // but no RPC methods would actually be allowed through
  const claimsWithoutMethods = (['read', 'write', 'deploy'] as const).filter(
    claimType => claims.includes(claimType) && getMethodsSelectedCount(claimType) === 0
  );
  const hasMethodGap = claimsWithoutMethods.length > 0;

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
        <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
      </div>
    );
  }

  const renderMethodSection = (claimType: 'read' | 'write' | 'deploy', title: string) => {
    const methods = RPC_METHODS_BY_CLAIM[claimType];
    const isExpanded = expandedSections[claimType];
    const hasClaim = claims.includes(claimType);
    const selectedCount = getMethodsSelectedCount(claimType);
    const totalCount = methods.length;

    return (
      <div className={`border rounded-lg ${hasClaim ? 'border-neutral-200' : 'border-neutral-100 bg-neutral-100'}`}>
        {/* Section header */}
        <div
          className={`flex items-center justify-between p-3 cursor-pointer ${hasClaim ? 'hover:bg-primary-50' : ''}`}
          onClick={() => hasClaim && toggleSection(claimType)}
        >
          <div className="flex items-center gap-2">
            {hasClaim ? (
              isExpanded ? (
                <ChevronDown className="w-4 h-4 text-neutral-500" />
              ) : (
                <ChevronRight className="w-4 h-4 text-neutral-500" />
              )
            ) : (
              <ChevronRight className="w-4 h-4 text-neutral-300" />
            )}
            <span className={`text-sm font-medium ${hasClaim ? 'text-neutral-700' : 'text-neutral-400'}`}>
              {title}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full ${
              hasClaim
                ? 'bg-primary-50 text-primary'
                : 'bg-neutral-100 text-neutral-400'
            }`}>
              {selectedCount} / {totalCount}
            </span>
          </div>
          {hasClaim && (
            <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
              <button
                type="button"
                className="text-xs text-primary hover:text-primary-600 font-medium"
                onClick={() => selectAllInSection(claimType)}
              >
                Select All
              </button>
              <span className="text-neutral-200">|</span>
              <button
                type="button"
                className="text-xs text-neutral-500 hover:text-neutral-700 font-medium"
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
            <p className="text-xs text-neutral-400 italic">
              Enable "{CLAIM_LABELS[claimType]}" claim to configure these methods
            </p>
          </div>
        )}

        {/* Methods grid */}
        {hasClaim && isExpanded && (
          <div className="border-t border-neutral-200 p-3 max-h-96 overflow-y-auto space-y-4">
            {Object.entries(METHOD_CATEGORIES[claimType]).map(([categoryLabel, categoryMethods]) => {
              const catMethodsSelected = allowedMethods.filter(m => (categoryMethods as readonly string[]).includes(m));
              const allCatSelected = catMethodsSelected.length === categoryMethods.length && categoryMethods.length > 0;

              const toggleCategory = (e: React.MouseEvent) => {
                e.stopPropagation();
                if (allCatSelected) {
                  // clear
                  setAllowedMethods(prev => prev.filter(m => !(categoryMethods as readonly string[]).includes(m)));
                } else {
                  // select all
                  setAllowedMethods(prev => {
                    const others = prev.filter(m => !(categoryMethods as readonly string[]).includes(m));
                    return [...others, ...categoryMethods];
                  });
                }
              };

              return (
                <div key={categoryLabel} className="space-y-2">
                  <div className="flex items-center justify-between border-b border-neutral-100 pb-1 mb-2">
                    <h4 className="text-[11px] font-semibold text-neutral-500 uppercase tracking-wider">{categoryLabel}</h4>
                    <button
                      type="button"
                      className="text-[10px] text-primary hover:text-primary-700 font-medium px-1.5 py-0.5 rounded hover:bg-primary-50 transition-colors"
                      onClick={toggleCategory}
                    >
                      {allCatSelected ? 'Clear' : 'Select All'}
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-1.5">
                    {(categoryMethods as readonly string[]).map((method: string) => (
                      <label
                        key={method}
                        className="flex items-center gap-2 p-1.5 rounded hover:bg-primary-50 cursor-pointer border border-transparent hover:border-neutral-100 transition-colors"
                        onClick={(e) => {
                          e.preventDefault(); // Prevent default double-toggle on labels
                          toggleMethod(method);
                        }}
                      >
                        <div className={`w-3.5 h-3.5 rounded border flex items-center justify-center flex-shrink-0 transition-colors ${
                          allowedMethods.includes(method)
                            ? 'bg-primary border-primary'
                            : 'border-neutral-300 bg-white'
                        }`}>
                          {allowedMethods.includes(method) && <Check className="w-2.5 h-2.5 text-white stroke-[3]" />}
                        </div>
                        <span className="text-xs font-mono text-neutral-700 truncate" title={method}>
                          {method}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      {/* Parent group context */}
      {parentGroup && (
        <div className="p-3 rounded-lg bg-sky-50 border border-sky-200 flex items-start gap-2">
          <Info className="w-4 h-4 text-sky-600 mt-0.5 flex-shrink-0" />
          <div className="text-xs text-sky-700">
            <p>
              Parent group "<strong>{parentGroup.name}</strong>" has claims:{' '}
              {parentGroup.claims.length > 0
                ? parentGroup.claims.map(c => CLAIM_LABELS[c]).join(', ')
                : 'none'}
            </p>
            <p className="mt-1">
              Effective claims at runtime will be the intersection of this group's claims with the parent's.
            </p>
          </div>
        </div>
      )}

      {/* Excess claims warning */}
      {parentGroup && parentGroup.claims.length > 0 && (() => {
        const excess = claims.filter(c => !parentGroup.claims.includes(c));
        if (excess.length === 0) return null;
        return (
          <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-amber-800">
              Claims {excess.map((c, i) => <span key={c}>{i > 0 && ', '}<strong>{CLAIM_LABELS[c]}</strong></span>)} exceed the parent group and will have no effect at runtime.
            </p>
          </div>
        );
      })()}

      {/* Claims section - moved to top */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          Claims
        </label>
        <p className="text-xs text-neutral-400 mb-2">
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
                  isImplied ? 'opacity-60 cursor-default' : 'hover:bg-primary-50 cursor-pointer'
                }`}
                onClick={() => !isImplied && toggleClaim(claim)}
              >
                <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
                  isChecked
                    ? isImplied
                      ? 'bg-primary-200 border-primary-200'
                      : 'bg-primary border-primary'
                    : 'border-neutral-300 bg-white'
                }`}>
                  {isChecked && <Check className="w-3 h-3 text-white" />}
                </div>
                <div>
                  <span className="text-sm font-medium text-neutral-900">
                    {CLAIM_LABELS[claim]}
                    {isImplied && (
                      <span className="text-xs font-normal text-neutral-400 ml-2">
                        (implied by {CLAIM_LABELS[implyingClaim]})
                      </span>
                    )}
                  </span>
                  <p className="text-xs text-neutral-400">{CLAIM_DESCRIPTIONS[claim]}</p>
                </div>
              </label>
            );
          })}
        </div>
        {claims.length === 0 && (
          <p className="text-xs text-error mt-1">Select at least one claim.</p>
        )}
      </div>

      {/* RPC Methods section - now grouped by claim */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          Allowed RPC Methods
        </label>
        <p className="text-xs text-neutral-400 mb-2">
          Methods are grouped by required claim. Enable a claim above to configure its methods.
        </p>
        {/* Method selections */}
        <div className="space-y-4 pt-2">
          <h4 className="text-sm font-medium text-neutral-800 border-b border-neutral-100 pb-2">RPC Methods</h4>
          
          {renderMethodSection('read', 'Read Methods')}
          {renderMethodSection('write', 'Write Methods')}
          {renderMethodSection('deploy', 'Advanced Tracing (Requires Deploy)')}
        </div>
        {hasMethodGap && (
          <p className="text-xs text-error mt-1">
            {claimsWithoutMethods.map(c => CLAIM_LABELS[c]).join(' and ')} claim{claimsWithoutMethods.length > 1 ? 's have' : ' has'} no methods selected.
          </p>
        )}
      </div>

      {/* Rate limits */}
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <label className="block text-sm font-medium text-neutral-700">
            Rate Limit (RPS)
          </label>
          <Input
            type="number"
            value={rateLimitRPS}
            onChange={e => setRateLimitRPS(e.target.value)}
            placeholder="100"
            min="0"
          />
          <p className="text-xs text-neutral-400">Requests per second</p>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium text-neutral-700">
            Rate Limit (Daily)
          </label>
          <Input
            type="number"
            value={rateLimitDaily}
            onChange={e => setRateLimitDaily(e.target.value)}
            placeholder="100000"
            min="0"
          />
          <p className="text-xs text-neutral-400">Requests per day</p>
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
        <Button type="submit" disabled={saving || claims.length === 0 || hasMethodGap} className="gap-2">
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
