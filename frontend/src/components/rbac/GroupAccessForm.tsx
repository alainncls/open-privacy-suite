import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { SetGroupAccessInput, PermissionPreset } from '@/types/rbac';
import {
  METHOD_SECTIONS,
  PERMISSION_PRESETS,
  getPresetMethods,
  deriveClaims,
  detectMatchingPreset,
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
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(null);
  const [isAdminPreset, setIsAdminPreset] = useState(false);
  const [rpcApiKey, setRpcApiKey] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Track whether the last method change came from a preset click (skip auto-detect)
  const [presetApplied, setPresetApplied] = useState(false);

  useEffect(() => {
    loadAccess();
  }, [groupId]);

  // Auto-detect preset whenever methods change (but skip if a preset was just applied)
  useEffect(() => {
    if (presetApplied) {
      setPresetApplied(false);
      return;
    }
    const match = detectMatchingPreset(allowedMethods);
    setSelectedPresetId(match);
    setIsAdminPreset(match === 'admin');
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
        // Admin detection: if all admin claims present, treat as admin preset
        if (access.claims?.includes('admin')) {
          const adminPreset = PERMISSION_PRESETS.find(p => p.id === 'admin');
          if (adminPreset) {
            const presetMethods = getPresetMethods(adminPreset);
            const methodSet = new Set(methods);
            if (presetMethods.every(m => methodSet.has(m)) && presetMethods.length === methodSet.size) {
              setIsAdminPreset(true);
            }
          }
        }
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

  const applyPreset = (preset: PermissionPreset) => {
    const methods = getPresetMethods(preset);
    setPresetApplied(true);
    setAllowedMethods(methods);
    setIsAdminPreset(preset.adminClaim === true);
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
      const claims = deriveClaims(allowedMethods, isAdminPreset);
      const input: SetGroupAccessInput = {
        allowed_methods: allowedMethods,
        claims: claims,
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

      {/* Preset cards */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Quick Start</label>
        <p className="text-xs text-neutral-400">Select a role to pre-fill permissions, or pick methods manually below.</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
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
          Bearer token sent to the upstream RPC proxy. Leave empty to use the global default.
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
