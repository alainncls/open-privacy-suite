import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Loader2, Plus, AlertCircle, Pencil, Trash2, Coins } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import type { TokenPrice, UpsertTokenPriceInput } from '@/types/compliance';

export default function TokenPriceList() {
  const { selectedOrg } = useComplianceOrgContext();
  const orgId = selectedOrg?.id;

  const [tokens, setTokens] = useState<TokenPrice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<TokenPrice | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TokenPrice | null>(null);

  // Form state
  const [formAddress, setFormAddress] = useState('');
  const [formSymbol, setFormSymbol] = useState('');
  const [formDecimals, setFormDecimals] = useState('18');
  const [formPrice, setFormPrice] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);

  const loadTokens = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.tokens.list(orgId);
      setTokens(response.data || []);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to load token prices');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTokens();
  }, [orgId]);

  const openCreateForm = () => {
    setEditing(null);
    setFormAddress('native');
    setFormSymbol('ETH');
    setFormDecimals('18');
    setFormPrice('');
    setFormError(null);
    setShowForm(true);
  };

  const openEditForm = (token: TokenPrice) => {
    setEditing(token);
    setFormAddress(token.token_address);
    setFormSymbol(token.symbol);
    setFormDecimals(String(token.decimals));
    setFormPrice(String(token.price_usd));
    setFormError(null);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    const address = editing ? editing.token_address : formAddress.trim().toLowerCase();
    if (!address) {
      setFormError('Token address is required');
      return;
    }

    const input: UpsertTokenPriceInput = {
      symbol: formSymbol.trim(),
      decimals: parseInt(formDecimals) || 18,
      price_usd: parseFloat(formPrice) || 0,
    };

    if (!input.symbol) {
      setFormError('Symbol is required');
      return;
    }
    if (input.price_usd <= 0) {
      setFormError('Price must be greater than 0');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      await complianceApi.tokens.upsert(orgId, address, input);
      setShowForm(false);
      loadTokens();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to save token price');
    } finally {
      setFormSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!orgId || !deleteTarget) return;
    try {
      await complianceApi.tokens.delete(orgId, deleteTarget.token_address);
      setDeleteTarget(null);
      loadTokens();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to delete token price');
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
        <h3 className="text-base font-medium text-[#374151]">Token Prices</h3>
        <Button size="sm" onClick={openCreateForm}>
          <Plus className="w-4 h-4 mr-1" />
          Add Token
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {tokens.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <Coins className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-2">No token prices configured</p>
          <p className="text-[#94A3B8] text-sm">
            Add token prices to enable USD value calculation for compliance checks
          </p>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Token Address</TableHead>
              <TableHead>Symbol</TableHead>
              <TableHead>Decimals</TableHead>
              <TableHead>Price (USD)</TableHead>
              <TableHead>Updated</TableHead>
              <TableHead className="w-[80px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tokens.map(token => (
              <TableRow key={token.id}>
                <TableCell className="font-mono text-xs">
                  {token.token_address === 'native' ? (
                    <Badge variant="info">native (ETH)</Badge>
                  ) : (
                    <span className="text-[#6B7280]">{token.token_address}</span>
                  )}
                </TableCell>
                <TableCell className="font-medium">{token.symbol}</TableCell>
                <TableCell>{token.decimals}</TableCell>
                <TableCell>${token.price_usd.toLocaleString()}</TableCell>
                <TableCell className="text-[#6B7280] text-sm">
                  {new Date(token.updated_at).toLocaleDateString()}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" onClick={() => openEditForm(token)}>
                      <Pencil className="w-4 h-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(token)}>
                      <Trash2 className="w-4 h-4 text-[#991B1B]" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={showForm} onOpenChange={open => { if (!open) setShowForm(false); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Token Price' : 'Add Token Price'}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {formError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Token Address
              </label>
              <Input
                value={formAddress}
                onChange={e => setFormAddress(e.target.value)}
                placeholder='native or 0x...'
                disabled={!!editing}
              />
              <p className="text-xs text-[#94A3B8] mt-1">
                Use "native" for the chain's native currency (ETH)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">Symbol</label>
              <Input
                value={formSymbol}
                onChange={e => setFormSymbol(e.target.value)}
                placeholder="ETH"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">Decimals</label>
              <Input
                type="number"
                value={formDecimals}
                onChange={e => setFormDecimals(e.target.value)}
                placeholder="18"
                min="0"
                max="36"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Price (USD)
              </label>
              <Input
                type="number"
                value={formPrice}
                onChange={e => setFormPrice(e.target.value)}
                placeholder="2500.00"
                min="0"
                step="0.01"
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {editing ? 'Update' : 'Add'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => { if (!open) setDeleteTarget(null); }}
        title="Delete Token Price"
        description={`Are you sure you want to delete the price for ${deleteTarget?.symbol || 'this token'}? Compliance checks will no longer be able to calculate USD values for transfers involving this token.`}
        confirmLabel="Delete"
        onConfirm={handleDelete}
        variant="destructive"
      />
    </div>
  );
}
