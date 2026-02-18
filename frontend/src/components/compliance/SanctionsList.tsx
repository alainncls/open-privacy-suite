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
import Pagination from '@/components/ui/Pagination';
import { Loader2, Plus, AlertCircle, ShieldBan, Trash2 } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import type { SanctionedAddress } from '@/types/compliance';

const PAGE_SIZE = 25;

export default function SanctionsList() {
  const { organizations } = useComplianceOrgContext();

  const [addresses, setAddresses] = useState<SanctionedAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SanctionedAddress | null>(null);

  // Form state
  const [formAddress, setFormAddress] = useState('');
  const [formReason, setFormReason] = useState('');
  const [formSource, setFormSource] = useState('');
  const [formOrgId, setFormOrgId] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);

  const loadAddresses = async (newOffset: number = offset) => {
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.sanctions.list({
        limit: PAGE_SIZE,
        offset: newOffset,
      });
      const page = response.data;
      setAddresses(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setAddresses([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load sanctioned addresses');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAddresses(0);
  }, []);

  const openCreateForm = () => {
    setFormAddress('');
    setFormReason('');
    setFormSource('');
    setFormOrgId('');
    setFormError(null);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formAddress.trim()) {
      setFormError('Address is required');
      return;
    }
    if (!formReason.trim()) {
      setFormError('Reason is required');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      await complianceApi.sanctions.add({
        address: formAddress.trim().toLowerCase(),
        reason: formReason.trim(),
        source: formSource.trim() || undefined,
        org_id: formOrgId || undefined,
      });
      setShowForm(false);
      loadAddresses(0);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to add sanctioned address');
    } finally {
      setFormSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await complianceApi.sanctions.remove(deleteTarget.id);
      setDeleteTarget(null);
      loadAddresses(offset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to remove sanctioned address');
    }
  };

  const getOrgName = (orgId?: string) => {
    if (!orgId) return null;
    const org = organizations.find(o => o.id === orgId);
    return org?.name || orgId.slice(0, 8);
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
        <h3 className="text-base font-medium text-[#374151]">Sanctioned Addresses</h3>
        <Button size="sm" onClick={openCreateForm}>
          <Plus className="w-4 h-4 mr-1" />
          Add Address
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {addresses.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <ShieldBan className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-2">No sanctioned addresses</p>
          <p className="text-[#94A3B8] text-sm">
            Add addresses to the sanctions list to block transfers involving them
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Added</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {addresses.map(addr => (
                <TableRow key={addr.id}>
                  <TableCell className="font-mono text-xs text-[#6B7280]">
                    {addr.address.slice(0, 10)}...{addr.address.slice(-6)}
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate">{addr.reason}</TableCell>
                  <TableCell className="text-[#6B7280] text-sm">{addr.source || '—'}</TableCell>
                  <TableCell>
                    {addr.org_id ? (
                      <Badge variant="outline">{getOrgName(addr.org_id)}</Badge>
                    ) : (
                      <Badge variant="warning">Global</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-[#6B7280] text-sm">
                    {new Date(addr.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(addr)}>
                      <Trash2 className="w-4 h-4 text-[#991B1B]" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            limit={PAGE_SIZE}
            offset={offset}
            onPageChange={newOffset => loadAddresses(newOffset)}
          />
        </>
      )}

      {/* Add Dialog */}
      <Dialog open={showForm} onOpenChange={open => { if (!open) setShowForm(false); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add Sanctioned Address</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {formError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">Address</label>
              <Input
                value={formAddress}
                onChange={e => setFormAddress(e.target.value)}
                placeholder="0x..."
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">Reason</label>
              <Input
                value={formReason}
                onChange={e => setFormReason(e.target.value)}
                placeholder="OFAC SDN list, etc."
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Source <span className="text-[#94A3B8] font-normal">(optional)</span>
              </label>
              <Input
                value={formSource}
                onChange={e => setFormSource(e.target.value)}
                placeholder="OFAC, Chainalysis, manual"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Scope
              </label>
              <select
                className="w-full rounded-md border border-[#E2E8F0] bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#8950FA]/40"
                value={formOrgId}
                onChange={e => setFormOrgId(e.target.value)}
              >
                <option value="">Global (all organizations)</option>
                {organizations.map(org => (
                  <option key={org.id} value={org.id}>{org.name}</option>
                ))}
              </select>
              <p className="text-xs text-[#94A3B8] mt-1">
                Global sanctions apply to all organizations
              </p>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Add to Sanctions
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => { if (!open) setDeleteTarget(null); }}
        title="Remove Sanctioned Address"
        description={`Are you sure you want to remove ${deleteTarget?.address || 'this address'} from the sanctions list? Transfers involving this address will no longer be blocked by sanctions screening.`}
        confirmLabel="Remove"
        onConfirm={handleDelete}
        variant="destructive"
      />
    </div>
  );
}
