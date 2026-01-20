import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Role, Claim } from '@/types/rbac';
import { ALL_CLAIMS, CLAIM_LABELS, CLAIM_DESCRIPTIONS } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { AlertCircle, Save, X, Loader2 } from 'lucide-react';

interface RoleFormProps {
  orgId: string;
  role?: Role;
  onClose: () => void;
  onSave: () => void;
}

export default function RoleForm({ orgId, role, onClose, onSave }: RoleFormProps) {
  const [name, setName] = useState(role?.name || '');
  const [description, setDescription] = useState(role?.description || '');
  const [claims, setClaims] = useState<Claim[]>(role?.claims || []);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleClaim = (claim: Claim) => {
    if (claims.includes(claim)) {
      setClaims(claims.filter(c => c !== claim));
    } else {
      setClaims([...claims, claim]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      if (role) {
        await rbacApi.roles.update(orgId, role.id, { name, description, claims });
      } else {
        await rbacApi.roles.create(orgId, { name, description, claims });
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save role:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save role. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  const getClaimColor = (claim: string, selected: boolean) => {
    const baseColors: Record<string, string> = {
      admin: 'border-red-500/50 bg-red-500/20 text-red-400',
      deployer: 'border-purple-500/50 bg-purple-500/20 text-purple-400',
      upgrade: 'border-orange-500/50 bg-orange-500/20 text-orange-400',
      writer: 'border-blue-500/50 bg-blue-500/20 text-blue-400',
      reader: 'border-green-500/50 bg-green-500/20 text-green-400',
    };
    if (selected) {
      return baseColors[claim] || 'border-primary-500/50 bg-primary-500/20 text-primary-400';
    }
    return 'border-white/20 bg-white/5 text-white/60 hover:border-white/30 hover:bg-white/10';
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
        <label className="block text-sm font-medium text-white/70">Name</label>
        <Input
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g., Developer, Auditor, Admin"
          required
        />
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Description (optional)
        </label>
        <Textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="Describe what this role can do..."
          className="h-20"
        />
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">Claims</label>
        <p className="text-xs text-white/40 mb-3">
          Select the permissions this role grants
        </p>
        <div className="grid grid-cols-2 gap-2">
          {ALL_CLAIMS.map(claim => (
            <button
              key={claim}
              type="button"
              onClick={() => toggleClaim(claim)}
              className={`p-3 rounded-lg border transition-all duration-200 text-left ${getClaimColor(
                claim,
                claims.includes(claim)
              )}`}
            >
              <div className="flex items-center gap-2">
                <div
                  className={`w-4 h-4 rounded border flex items-center justify-center ${
                    claims.includes(claim)
                      ? 'bg-current border-current'
                      : 'border-white/30'
                  }`}
                >
                  {claims.includes(claim) && (
                    <svg
                      className="w-3 h-3 text-white"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={3}
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  )}
                </div>
                <span className="font-medium text-sm">{CLAIM_LABELS[claim]}</span>
              </div>
              <p className="text-xs opacity-70 mt-1 ml-6">
                {CLAIM_DESCRIPTIONS[claim]}
              </p>
            </button>
          ))}
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
        <Button type="submit" disabled={saving} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {role ? 'Update' : 'Create'} Role
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
