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
import type { APIKey } from '@/types/compliance';

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

  useEffect(() => {
    loadKeys();
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
