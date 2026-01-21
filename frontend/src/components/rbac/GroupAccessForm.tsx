import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Claim, SetGroupAccessInput } from '@/types/rbac';
import { ALL_CLAIMS, CLAIM_LABELS, CLAIM_DESCRIPTIONS } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { AlertCircle, Save, X, Loader2, Check } from 'lucide-react';

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
  const [allowedMethods, setAllowedMethods] = useState('');
  const [defaultClaims, setDefaultClaims] = useState<Claim[]>([]);
  const [rateLimitRPS, setRateLimitRPS] = useState<string>('');
  const [rateLimitDaily, setRateLimitDaily] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAccess();
  }, [groupId]);

  const loadAccess = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.groups.getAccess(orgId, groupId);
      const access = response.data;
      if (access) {
        setAllowedMethods((access.allowed_methods || []).join('\n'));
        setDefaultClaims(access.default_claims || []);
        setRateLimitRPS(access.rate_limit_rps?.toString() || '');
        setRateLimitDaily(access.rate_limit_daily?.toString() || '');
      }
    } catch {
      // No access settings yet, that's OK
    } finally {
      setLoading(false);
    }
  };

  const parseList = (value: string) => {
    return value
      .split(/[\s\n,]+/)
      .map(v => v.trim())
      .filter(v => v.length > 0);
  };

  const toggleClaim = (claim: Claim) => {
    setDefaultClaims(prev =>
      prev.includes(claim)
        ? prev.filter(c => c !== claim)
        : [...prev, claim]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const input: SetGroupAccessInput = {
        allowed_methods: parseList(allowedMethods),
        default_claims: defaultClaims,
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
        <Loader2 className="w-6 h-6 text-white/40 animate-spin" />
      </div>
    );
  }

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
          Allowed RPC Methods
        </label>
        <Textarea
          value={allowedMethods}
          onChange={e => setAllowedMethods(e.target.value)}
          placeholder="eth_call&#10;eth_getBalance&#10;eth_sendTransaction"
          className="h-24 font-mono text-sm"
        />
        <p className="text-xs text-white/40">
          RPC methods this group can call (one per line). Leave empty for all methods.
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Default Claims
        </label>
        <p className="text-xs text-white/40 mb-2">
          Claims applied to unregistered contracts (not in the Contracts list)
        </p>
        <div className="space-y-2">
          {ALL_CLAIMS.map(claim => (
            <label
              key={claim}
              className="flex items-start gap-3 p-2 rounded-lg hover:bg-white/5 cursor-pointer"
              onClick={() => toggleClaim(claim)}
            >
              <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
                defaultClaims.includes(claim)
                  ? 'bg-primary-500 border-primary-500'
                  : 'border-white/30 bg-white/5'
              }`}>
                {defaultClaims.includes(claim) && <Check className="w-3 h-3 text-white" />}
              </div>
              <div>
                <span className="text-sm font-medium">{CLAIM_LABELS[claim]}</span>
                <p className="text-xs text-white/40">{CLAIM_DESCRIPTIONS[claim]}</p>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <label className="block text-sm font-medium text-white/70">
            Rate Limit (RPS)
          </label>
          <Input
            type="number"
            value={rateLimitRPS}
            onChange={e => setRateLimitRPS(e.target.value)}
            placeholder="100"
            min="0"
          />
          <p className="text-xs text-white/40">Requests per second</p>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium text-white/70">
            Rate Limit (Daily)
          </label>
          <Input
            type="number"
            value={rateLimitDaily}
            onChange={e => setRateLimitDaily(e.target.value)}
            placeholder="100000"
            min="0"
          />
          <p className="text-xs text-white/40">Requests per day</p>
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
              Save Access Settings
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
