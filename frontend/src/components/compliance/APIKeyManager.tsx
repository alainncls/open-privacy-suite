import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Loader2, Plus, AlertCircle, Key, Copy, Check, Trash2, AlertTriangle } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import type { APIKey, ExternalRatesSettings, PriceChangeLog } from '@/types/compliance';

function getKeyStatus(key: APIKey): 'active' | 'revoked' | 'expired' {
  if (key.revoked_at) return 'revoked';
  if (key.expires_at && new Date(key.expires_at) < new Date()) return 'expired';
  return 'active';
}

const statusBadgeVariant: Record<string, 'success' | 'secondary' | 'destructive'> = {
  active: 'success',
  revoked: 'secondary',
  expired: 'destructive',
};

export default function APIKeyManager() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<APIKey | null>(null);

  // Create form state
  const [formName, setFormName] = useState('');
  const [formExpiryDays, setFormExpiryDays] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);

  // Created key display
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  // Security settings
  const [, setSettings] = useState<ExternalRatesSettings | null>(null);
  const [settingsForm, setSettingsForm] = useState({ max_price_deviation_pct: 0, price_update_cooldown_minutes: 0 });
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [settingsSuccess, setSettingsSuccess] = useState(false);

  // Price change log
  const [priceChanges, setPriceChanges] = useState<PriceChangeLog[]>([]);

  const loadKeys = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.apiKeys.list();
      setKeys(response.data.data || []);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to load API keys');
    } finally {
      setLoading(false);
    }
  };

  const loadSettings = async () => {
    try {
      const response = await complianceApi.externalRatesSettings.get();
      setSettings(response.data);
      setSettingsForm({
        max_price_deviation_pct: response.data.max_price_deviation_pct,
        price_update_cooldown_minutes: response.data.price_update_cooldown_minutes,
      });
    } catch {
      // Settings may not exist yet, that's fine
    }
  };

  const loadPriceChanges = async () => {
    try {
      const response = await complianceApi.priceChangeLog.list({ limit: 20 });
      setPriceChanges(response.data.data || []);
    } catch {
      // Ignore errors loading price changes
    }
  };

  const handleSaveSettings = async () => {
    try {
      setSettingsSaving(true);
      setSettingsError(null);
      setSettingsSuccess(false);
      const response = await complianceApi.externalRatesSettings.update(settingsForm);
      setSettings(response.data);
      setSettingsSuccess(true);
      setTimeout(() => setSettingsSuccess(false), 2000);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setSettingsError(axiosError.response?.data?.error || 'Failed to save settings');
    } finally {
      setSettingsSaving(false);
    }
  };

  useEffect(() => {
    loadKeys();
    loadSettings();
    loadPriceChanges();
  }, []);

  const openCreateDialog = () => {
    setFormName('');
    setFormExpiryDays('');
    setFormError(null);
    setShowCreateDialog(true);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = formName.trim();
    if (!name) {
      setFormError('Name is required');
      return;
    }

    const expiryDays = formExpiryDays ? parseInt(formExpiryDays) : undefined;
    if (formExpiryDays && (isNaN(expiryDays!) || expiryDays! <= 0)) {
      setFormError('Expiry must be a positive number of days');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      const response = await complianceApi.apiKeys.create(name, expiryDays);
      setShowCreateDialog(false);
      setCreatedKey(response.data.key);
      loadKeys();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to create API key');
    } finally {
      setFormSaving(false);
    }
  };

  const handleRevoke = async () => {
    if (!revokeTarget) return;
    try {
      await complianceApi.apiKeys.revoke(revokeTarget.id);
      setRevokeTarget(null);
      loadKeys();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to revoke API key');
      setRevokeTarget(null);
    }
  };

  const copyKeyToClipboard = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-[#94A3B8] animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-medium text-[#374151]">API Keys</h3>
        <Button size="sm" onClick={openCreateDialog}>
          <Plus className="w-4 h-4 mr-1" />
          Create API Key
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {keys.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <Key className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-2">No API keys</p>
          <p className="text-[#94A3B8] text-sm">
            Create an API key to allow programmatic access to the compliance API
          </p>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Key Prefix</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Last Used</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="w-[50px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map(apiKey => {
              const status = getKeyStatus(apiKey);
              return (
                <TableRow key={apiKey.id}>
                  <TableCell className="font-medium">{apiKey.name}</TableCell>
                  <TableCell className="font-mono text-xs text-[#6B7280]">
                    {apiKey.key_prefix}...
                  </TableCell>
                  <TableCell className="text-[#6B7280] text-sm">
                    {new Date(apiKey.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell className="text-[#6B7280] text-sm">
                    {apiKey.last_used_at
                      ? new Date(apiKey.last_used_at).toLocaleDateString()
                      : 'Never'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusBadgeVariant[status]}>{status}</Badge>
                  </TableCell>
                  <TableCell>
                    {status === 'active' && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setRevokeTarget(apiKey)}
                      >
                        <Trash2 className="w-4 h-4 text-[#991B1B]" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}

      {/* External Rates Security Settings */}
      <Card>
        <CardContent className="p-6 space-y-4">
          <h3 className="text-base font-medium text-[#374151]">External Rates Security</h3>

          {settingsError && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {settingsError}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Max Price Deviation (%)
              </label>
              <Input
                type="number"
                value={settingsForm.max_price_deviation_pct}
                onChange={e => setSettingsForm(prev => ({ ...prev, max_price_deviation_pct: parseFloat(e.target.value) || 0 }))}
                min="0"
                step="0.1"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Price Update Cooldown (minutes)
              </label>
              <Input
                type="number"
                value={settingsForm.price_update_cooldown_minutes}
                onChange={e => setSettingsForm(prev => ({ ...prev, price_update_cooldown_minutes: parseInt(e.target.value) || 0 }))}
                min="0"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button size="sm" onClick={handleSaveSettings} disabled={settingsSaving}>
              {settingsSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Save Settings
            </Button>
            {settingsSuccess && (
              <span className="text-sm text-[#22C55E] flex items-center gap-1">
                <Check className="w-4 h-4" /> Saved
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Price Change Audit Log */}
      <Card>
        <CardContent className="p-6 space-y-4">
          <h3 className="text-base font-medium text-[#374151]">Price Change Audit Log</h3>

          {priceChanges.length === 0 ? (
            <p className="text-[#6B7280] text-sm py-4 text-center">No price changes recorded</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>API Key</TableHead>
                  <TableHead>Token</TableHead>
                  <TableHead>Old Price → New Price</TableHead>
                  <TableHead>Deviation</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>IP Changed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {priceChanges.map(log => (
                  <TableRow key={log.id}>
                    <TableCell className="text-[#6B7280] text-sm whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-sm">{log.api_key_name}</TableCell>
                    <TableCell className="font-mono text-xs">{log.symbol}</TableCell>
                    <TableCell className="text-sm">
                      {log.old_price != null ? `$${log.old_price.toFixed(2)}` : 'N/A'}
                      {' → '}
                      ${log.new_price.toFixed(2)}
                    </TableCell>
                    <TableCell className="text-sm">
                      {log.deviation_pct != null ? `${log.deviation_pct.toFixed(1)}%` : 'N/A'}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-[#6B7280]">{log.ip_address}</TableCell>
                    <TableCell>
                      {log.ip_changed ? (
                        <AlertTriangle className="w-4 h-4 text-[#F97316]" />
                      ) : (
                        <span className="text-[#6B7280] text-sm">No</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={open => { if (!open) setShowCreateDialog(false); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreate} className="space-y-4">
            {formError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Name <span className="text-[#991B1B]">*</span>
              </label>
              <Input
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="e.g., Production backend"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Expires in (days)
              </label>
              <Input
                type="number"
                value={formExpiryDays}
                onChange={e => setFormExpiryDays(e.target.value)}
                placeholder="Leave empty for no expiration"
                min="1"
              />
              <p className="text-xs text-[#94A3B8] mt-1">
                Optional. Leave empty for a key that does not expire.
              </p>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowCreateDialog(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Create
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Created Key Display Dialog */}
      <Dialog open={!!createdKey} onOpenChange={open => { if (!open) setCreatedKey(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-start gap-2 p-3 rounded-lg bg-[#FEF3C7] border border-[#FDE68A] text-[#92400E] text-sm">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Copy this key now. You will not be able to see it again.
              </span>
            </div>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm font-mono break-all bg-[#F8FAFC] p-2 rounded border border-[#E2E8F0]">
                    {createdKey}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={copyKeyToClipboard}
                    className="shrink-0"
                  >
                    {copiedKey ? (
                      <Check className="w-4 h-4 text-[#22C55E]" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>

            <DialogFooter>
              <Button onClick={() => setCreatedKey(null)}>
                Done
              </Button>
            </DialogFooter>
          </div>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={open => { if (!open) setRevokeTarget(null); }}
        title="Revoke API Key"
        description={`Are you sure you want to revoke the API key "${revokeTarget?.name || ''}"? This action cannot be undone. Any applications using this key will lose access.`}
        confirmLabel="Revoke"
        onConfirm={handleRevoke}
        variant="destructive"
      />
    </div>
  );
}
