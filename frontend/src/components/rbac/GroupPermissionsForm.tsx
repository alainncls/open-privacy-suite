import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { GroupPermissions } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { AlertCircle, Save, X, Loader2 } from 'lucide-react';

interface GroupPermissionsFormProps {
  orgId: string;
  groupId: string;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupPermissionsForm({
  orgId,
  groupId,
  onClose,
  onSave,
}: GroupPermissionsFormProps) {
  const [loading, setLoading] = useState(true);
  const [allowAddresses, setAllowAddresses] = useState('');
  const [ownedAddresses, setOwnedAddresses] = useState('');
  const [rateLimitRPS, setRateLimitRPS] = useState<string>('');
  const [rateLimitDaily, setRateLimitDaily] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadPermissions();
  }, [groupId]);

  const loadPermissions = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.groups.getPermissions(orgId, groupId);
      const perms = response.data;
      if (perms) {
        setAllowAddresses((perms.allow_addresses || []).join('\n'));
        setOwnedAddresses((perms.owned_addresses || []).join('\n'));
        setRateLimitRPS(perms.rate_limit_rps?.toString() || '');
        setRateLimitDaily(perms.rate_limit_daily?.toString() || '');
      }
    } catch {
      // No permissions yet, that's OK
    } finally {
      setLoading(false);
    }
  };

  const parseList = (value: string, separator: RegExp = /[\s,]+/) => {
    return value
      .split(separator)
      .map(v => v.trim())
      .filter(v => v.length > 0);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const permissions: Partial<GroupPermissions> = {
        allow_addresses: parseList(allowAddresses, /[\s\n,]+/),
        owned_addresses: parseList(ownedAddresses, /[\s\n,]+/),
        rate_limit_rps: rateLimitRPS ? parseInt(rateLimitRPS, 10) : null,
        rate_limit_daily: rateLimitDaily ? parseInt(rateLimitDaily, 10) : null,
      };

      await rbacApi.groups.setPermissions(orgId, groupId, permissions);
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save permissions:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save permissions. Please try again.');
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

      <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 mb-4">
        <p className="text-sm text-blue-400">
          <strong>Note:</strong> Allowed methods are now configured on Roles, not Groups.
          Edit the group's assigned Role to change allowed methods.
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Allowed Addresses
        </label>
        <Textarea
          value={allowAddresses}
          onChange={e => setAllowAddresses(e.target.value)}
          placeholder="0x1234...&#10;0x5678..."
          className="h-24 font-mono text-sm"
        />
        <p className="text-xs text-white/40">
          Addresses this group can interact with (one per line)
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Owned Addresses
        </label>
        <Textarea
          value={ownedAddresses}
          onChange={e => setOwnedAddresses(e.target.value)}
          placeholder="0xabcd...&#10;0xefgh..."
          className="h-24 font-mono text-sm"
        />
        <p className="text-xs text-white/40">
          Addresses this group owns (one per line)
        </p>
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
              Save Permissions
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
