import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { SetGroupAccessInput, PermissionPreset } from '@/types/rbac';
import {
  METHOD_SECTIONS,
  PERMISSION_PRESETS,
  getPresetMethods,
  detectMatchingPreset,
  ExpandClaims,
  Claim,
  CLAIM_LABELS,
  CLAIM_DESCRIPTIONS,
} from '@/types/rbac';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2, Check, Wallet, Server, Code, ShieldCheck } from 'lucide-react';

const PRESET_ICONS: Record<string, React.ElementType> = {
  Wallet,
  Server,
  Code,
  ShieldCheck,
};

interface GroupAccessFormProps {
  orgId: string;
  groupId: string;
  // When the group is a full org admin, claims are not configurable here — the
  // resolver grants all claims on every org contract automatically (RD-968 Gap 1).
  // The claims editor is replaced by an explanatory banner and claims are saved
  // empty; the backend rejects a non-empty claims list on org-admin groups.
  isOrgAdmin?: boolean;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupAccessForm({
  orgId,
  groupId,
  isOrgAdmin = false,
  onClose,
  onSave,
}: GroupAccessFormProps) {
  const [loading, setLoading] = useState(true);
  const [allowedMethods, setAllowedMethods] = useState<string[]>([]);
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(null);
  const [selectedClaims, setSelectedClaims] = useState<Claim[]>([]);
  const [rpcApiKey, setRpcApiKey] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Track whether the last method change came from a preset click (skip auto-detect)
  const [presetApplied, setPresetApplied] = useState(false);
  // Extra RPC namespaces from server config (chain-specific methods)
  const [extraNamespaces, setExtraNamespaces] = useState<Record<string, string[]>>({});
  // Wildcard-enabled namespaces: namespace name → { prefix, deny[] }. When a
  // namespace appears here the form renders a single "Allow all <prefix>*"
  // toggle that, when checked, stores the literal "<prefix>*" glob in
  // allowed_methods (the backend honors it via HasMethod + MatchWildcard).
  const [extraWildcards, setExtraWildcards] = useState<Record<string, { prefix: string; deny?: string[] }>>({});

  // reason: intentional reload-on-groupId. loadAccess/loadExtraNamespaces are
  // non-memoised helpers that read current state via closure; adding them to
  // deps would require useCallback and risk a refetch loop.
  useEffect(() => {
    loadAccess();
    loadExtraNamespaces();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupId]);

  // Auto-detect preset whenever methods change (but skip if a preset was just applied)
  // reason: this effect must fire only when allowedMethods changes. presetApplied
  // is read as a one-shot guard that this effect itself resets; including it as a
  // dep would refire the effect on that reset and defeat the skip. Intentionally
  // omitted.
  useEffect(() => {
    if (presetApplied) {
      setPresetApplied(false);
      return;
    }
    const match = detectMatchingPreset(allowedMethods);
    setSelectedPresetId(match);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allowedMethods]);

  const loadAccess = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.groups.getAccess(orgId, groupId);
      const access = response.data;
      if (access) {
        const methods = (access.allowed_methods || []).filter((m: string) => m !== '*');
        setAllowedMethods(methods);
        setRpcApiKey(access.rpc_api_key || '');
        setSelectedClaims(access.claims || []);
      }
    } catch {
      // No access settings yet, that's OK
    } finally {
      setLoading(false);
    }
  };

  const loadExtraNamespaces = async () => {
    try {
      const response = await rbacApi.status.get();
      const ns = response.data?.methods?.extra_namespaces;
      if (ns && Object.keys(ns).length > 0) {
        setExtraNamespaces(ns);
      }
      const wc = response.data?.methods?.extra_wildcards;
      if (wc && Object.keys(wc).length > 0) {
        setExtraWildcards(wc);
      }
    } catch {
      // Non-critical — extra namespaces just won't show
    }
  };

  const toggleWildcard = (prefix: string) => {
    const glob = `${prefix}*`;
    setAllowedMethods(prev =>
      prev.includes(glob)
        ? prev.filter(m => m !== glob)
        : [...prev, glob]
    );
  };

  const toggleMethod = (method: string) => {
    setAllowedMethods(prev =>
      prev.includes(method)
        ? prev.filter(m => m !== method)
        : [...prev, method]
    );
  };

  const applyPreset = (preset: PermissionPreset) => {
    const methods = getPresetMethods(preset);
    setPresetApplied(true);
    setAllowedMethods(methods);
    setSelectedPresetId(preset.id);
  };

  const selectAllInSection = (methods: readonly string[]) => {
    setAllowedMethods(prev => {
      const others = prev.filter(m => !methods.includes(m));
      return [...others, ...methods];
    });
  };

  const clearSection = (methods: readonly string[]) => {
    setAllowedMethods(prev =>
      prev.filter(m => !methods.includes(m))
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const input: SetGroupAccessInput = {
        allowed_methods: allowedMethods,
        // Org-admin groups receive all claims automatically; claims are not
        // applicable and the backend rejects a non-empty list (RD-968 Gap 1).
        claims: isOrgAdmin ? [] : ExpandClaims(selectedClaims),
        rpc_api_key: rpcApiKey || null,
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

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      {/* Operational Claims. On a full org-admin group these don't apply — the
          resolver grants all claims on every org contract automatically
          (RD-968 Gap 1) — so show a banner instead of the editor. */}
      {isOrgAdmin ? (
        <div className="flex items-start gap-3 bg-primary-50 border border-primary-200 rounded-lg p-4">
          <ShieldCheck className="w-5 h-5 text-primary-700 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-primary-700">Operational Claims</h3>
            <p className="text-xs text-neutral-600 mt-0.5">
              This is a full org-admin group. Members automatically receive all claims
              (admin, deploy, upgrade) on every contract in the organization, so the
              claims list does not apply. Configure the allowed RPC methods below.
            </p>
          </div>
        </div>
      ) : (
      <div className="space-y-3 bg-neutral-50 border border-neutral-200 rounded-lg p-4">
        <div>
          <h3 className="text-sm font-semibold text-neutral-900">Operational Claims</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Explicit permissions for proxy management. These are required for advanced operations independent of RPC methods.
          </p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(['admin', 'deploy', 'upgrade'] as Claim[]).map(claim => {
            const isChecked = selectedClaims.includes(claim);
            // If admin is checked, deploy and upgrade are effectively checked/disabled
            const isAdminChecked = selectedClaims.includes('admin');
            const isDisabled = (claim === 'deploy' || claim === 'upgrade') && isAdminChecked;
            const effectivelyChecked = isChecked || isDisabled;

            return (
              <label
                key={claim}
                className={cn(
                  'flex items-start gap-3 p-3 rounded-lg border transition-colors',
                  effectivelyChecked ? 'border-primary bg-white shadow-sm' : 'border-neutral-200 hover:border-primary-200 bg-white',
                  isDisabled && 'opacity-60 cursor-not-allowed'
                )}
                onClick={(e) => {
                  e.preventDefault();
                  if (isDisabled) return;
                  
                  setSelectedClaims(prev => {
                    if (prev.includes(claim)) {
                      return prev.filter(c => c !== claim);
                    } else {
                      const newClaims = [...prev, claim];
                      if (claim === 'admin') {
                        // Admin implies others, so we visually check them too
                        if (!newClaims.includes('deploy')) newClaims.push('deploy');
                        if (!newClaims.includes('upgrade')) newClaims.push('upgrade');
                      }
                      return newClaims;
                    }
                  });
                }}
              >
                <div className={cn(
                  'w-4 h-4 mt-0.5 rounded border flex items-center justify-center flex-shrink-0 transition-colors',
                  effectivelyChecked ? 'bg-primary border-primary' : 'border-neutral-300 bg-white'
                )}>
                  {effectivelyChecked && <Check className="w-3 h-3 text-white stroke-[3]" />}
                </div>
                <div>
                  <div className="text-sm font-semibold text-neutral-900">{CLAIM_LABELS[claim]}</div>
                  <div className="text-[11px] text-neutral-500 leading-tight mt-0.5">{CLAIM_DESCRIPTIONS[claim]}</div>
                </div>
              </label>
            );
          })}
        </div>
      </div>
      )}

      {/* Preset cards */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Quick Start</label>
        <p className="text-xs text-neutral-400">Select a role to pre-fill permissions, or pick methods manually below.</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {PERMISSION_PRESETS.map(preset => {
            const IconComponent = PRESET_ICONS[preset.icon] || ShieldCheck;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => applyPreset(preset)}
                className={cn(
                  'flex flex-col items-start gap-1 p-3 rounded-lg border-2 text-left transition-all',
                  selectedPresetId === preset.id
                    ? 'border-primary bg-primary-50'
                    : 'border-neutral-200 hover:border-primary-200'
                )}
              >
                <IconComponent className="w-5 h-5 text-primary" />
                <span className="text-sm font-semibold text-neutral-900">{preset.name}</span>
                <span className="text-[11px] text-neutral-500">{preset.description}</span>
                <span className="text-[10px] text-neutral-400">{getPresetMethods(preset).length} methods</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Method sections */}
      <div className="space-y-4">
        <label className="block text-sm font-medium text-neutral-700">
          Allowed RPC Methods
        </label>
        <p className="text-xs text-neutral-400">
          Methods are grouped by role. Check individual methods or use presets above.
        </p>

        {(Object.entries(METHOD_SECTIONS) as [keyof typeof METHOD_SECTIONS, typeof METHOD_SECTIONS[keyof typeof METHOD_SECTIONS]][]).map(([sectionName, section]) => {
          const sectionMethods = section.methods;
          const selectedCount = allowedMethods.filter(m => (sectionMethods as readonly string[]).includes(m)).length;
          const sectionLabel = sectionName === 'Wallet User'
            ? sectionName
            : `+ ${sectionName}`;

          return (
            <div key={sectionName} className="border rounded-lg border-neutral-200">
              {/* Section header */}
              <div className="flex items-center justify-between p-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-neutral-700">{sectionLabel}</span>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-primary-50 text-primary">
                    {selectedCount} / {sectionMethods.length}
                  </span>
                </div>
                <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                  <button
                    type="button"
                    className="text-xs text-primary hover:text-primary-600 font-medium"
                    onClick={() => selectAllInSection(sectionMethods)}
                  >
                    Select All
                  </button>
                  <span className="text-neutral-200">|</span>
                  <button
                    type="button"
                    className="text-xs text-neutral-500 hover:text-neutral-700 font-medium"
                    onClick={() => clearSection(sectionMethods)}
                  >
                    Clear
                  </button>
                </div>
              </div>

              {/* Description */}
              <div className="px-3 pb-2">
                <p className="text-xs text-neutral-400">{section.description}</p>
              </div>

              {/* Methods grid */}
              <div className="border-t border-neutral-200 p-3">
                <div className="grid grid-cols-2 gap-1.5">
                  {sectionMethods.map((method: string) => (
                    <label
                      key={method}
                      className="flex items-center gap-2 p-1.5 rounded hover:bg-primary-50 cursor-pointer border border-transparent hover:border-neutral-100 transition-colors"
                      onClick={(e) => {
                        e.preventDefault();
                        toggleMethod(method);
                      }}
                    >
                      <div className={cn(
                        'w-3.5 h-3.5 rounded border flex items-center justify-center flex-shrink-0 transition-colors',
                        allowedMethods.includes(method)
                          ? 'bg-primary border-primary'
                          : 'border-neutral-300 bg-white'
                      )}>
                        {allowedMethods.includes(method) && <Check className="w-2.5 h-2.5 text-white stroke-[3]" />}
                      </div>
                      <span className="text-xs font-mono text-neutral-700 truncate" title={method}>
                        {method}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          );
        })}

        {/* Extra RPC namespaces (chain-specific, from server config) */}
        {Array.from(new Set([
          ...Object.keys(extraNamespaces),
          ...Object.keys(extraWildcards),
        ])).sort().map((nsName) => {
          const nsMethods = extraNamespaces[nsName] ?? [];
          const wildcard = extraWildcards[nsName];
          const selectedCount = allowedMethods.filter(m => nsMethods.includes(m)).length;
          const wildcardGlob = wildcard ? `${wildcard.prefix}*` : null;
          const wildcardOn = wildcardGlob ? allowedMethods.includes(wildcardGlob) : false;
          return (
            <div key={nsName} className="border rounded-lg border-neutral-200">
              <div className="flex items-center justify-between p-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-neutral-700">{nsName}</span>
                  {nsMethods.length > 0 && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-neutral-100 text-neutral-600">
                      {selectedCount} / {nsMethods.length}
                    </span>
                  )}
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-50 text-amber-600 font-medium">
                    Extension
                  </span>
                </div>
                {nsMethods.length > 0 && (
                  <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                    <button
                      type="button"
                      className="text-xs text-primary hover:text-primary-600 font-medium"
                      onClick={() => selectAllInSection(nsMethods)}
                    >
                      Select All
                    </button>
                    <span className="text-neutral-200">|</span>
                    <button
                      type="button"
                      className="text-xs text-neutral-500 hover:text-neutral-700 font-medium"
                      onClick={() => clearSection(nsMethods)}
                    >
                      Clear
                    </button>
                  </div>
                )}
              </div>
              <div className="px-3 pb-2">
                <p className="text-xs text-neutral-400">Chain-specific methods configured by the operator.</p>
              </div>

              {/* Wildcard passthrough toggle — checked = "<prefix>*" stored in allowed_methods */}
              {wildcard && (
                <div className="border-t border-neutral-200 p-3 bg-amber-50/30">
                  <label
                    className="flex items-start gap-2 p-1.5 rounded hover:bg-amber-50 cursor-pointer border border-transparent hover:border-amber-200 transition-colors"
                    onClick={(e) => {
                      e.preventDefault();
                      toggleWildcard(wildcard.prefix);
                    }}
                  >
                    <div className={cn(
                      'w-3.5 h-3.5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors',
                      wildcardOn ? 'bg-amber-500 border-amber-500' : 'border-neutral-300 bg-white'
                    )}>
                      {wildcardOn && <Check className="w-2.5 h-2.5 text-white stroke-[3]" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-neutral-800 font-semibold">{wildcard.prefix}*</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 font-medium uppercase">
                          Passthrough
                        </span>
                      </div>
                      <p className="text-[11px] text-neutral-500 mt-0.5">
                        Allow any method starting with <code>{wildcard.prefix}</code>. The proxy forwards these to the upstream node as-is —
                        no contract access check, no response redaction. Use only when you trust the upstream chain's namespace.
                      </p>
                    </div>
                  </label>

                  {/* Operator deny list — visually marked as a denied set, distinct from the amber wildcard tone */}
                  {wildcard.deny && wildcard.deny.length > 0 && (
                    <div
                      className="mt-2 p-2 rounded border border-error/30 bg-error-light/40"
                      onClick={e => e.stopPropagation()}
                    >
                      <div className="flex items-center gap-1.5 mb-1.5">
                        <X className="w-3 h-3 text-error-dark stroke-[3]" />
                        <span className="text-[11px] font-semibold text-error-dark uppercase tracking-wide">
                          Always denied · operator block list
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {wildcard.deny.map((d) => (
                          <span
                            key={d}
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-white border border-error/40 text-[10px] font-mono text-error-dark"
                            title={`Rejected even when ${wildcard.prefix}* is enabled`}
                          >
                            <X className="w-2.5 h-2.5" />
                            {d}
                          </span>
                        ))}
                      </div>
                      <p className="text-[10px] text-neutral-500 mt-1.5">
                        Rejected even with the wildcard above enabled. Configured by the operator at startup; not editable from this form.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Explicit chain-specific methods */}
              {nsMethods.length > 0 && (
                <div className="border-t border-neutral-200 p-3">
                  <div className="grid grid-cols-2 gap-1.5">
                    {nsMethods.map((method) => (
                      <label
                        key={method}
                        className="flex items-center gap-2 p-1.5 rounded hover:bg-primary-50 cursor-pointer border border-transparent hover:border-neutral-100 transition-colors"
                        onClick={(e) => {
                          e.preventDefault();
                          toggleMethod(method);
                        }}
                      >
                        <div className={cn(
                          'w-3.5 h-3.5 rounded border flex items-center justify-center flex-shrink-0 transition-colors',
                          allowedMethods.includes(method)
                            ? 'bg-primary border-primary'
                            : 'border-neutral-300 bg-white'
                        )}>
                          {allowedMethods.includes(method) && <Check className="w-2.5 h-2.5 text-white stroke-[3]" />}
                        </div>
                        <span className="text-xs font-mono text-neutral-700 truncate" title={method}>
                          {method}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* RPC API Key */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          RPC API Key
        </label>
        <Input
          type="text"
          value={rpcApiKey}
          onChange={e => setRpcApiKey(e.target.value)}
          placeholder="Optional — overrides global RPC_API_KEY for this group"
        />
        <p className="text-xs text-neutral-400">
          Sent to the upstream RPC proxy. Leave empty to use the global default.
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
        <Button type="submit" disabled={saving || allowedMethods.length === 0} className="gap-2">
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
