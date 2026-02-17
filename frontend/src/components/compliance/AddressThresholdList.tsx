import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import { Loader2, Plus, AlertCircle, MapPin, Trash2, Pencil } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import type { AddressThresholdOverride } from '@/types/compliance';

const PAGE_SIZE = 25;

export default function AddressThresholdList() {
  const { selectedOrg } = useComplianceOrgContext();
  const orgId = selectedOrg?.id;

  const [overrides, setOverrides] = useState<AddressThresholdOverride[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AddressThresholdOverride | null>(null);

  // Form state
  const [formAddress, setFormAddress] = useState('');
  const [formThreshold, setFormThreshold] = useState('');
  const [formNote, setFormNote] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);
  const [editMode, setEditMode] = useState(false);

  const loadOverrides = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.addressThresholds.list(orgId, {
        limit: PAGE_SIZE,
        offset: newOffset,
      });
      const page = response.data;
      setOverrides(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setOverrides([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load address thresholds');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (orgId) loadOverrides(0);
  }, [orgId]);

  const openCreateForm = () => {
    setFormAddress('');
    setFormThreshold('0');
    setFormNote('');
    setFormError(null);
    setEditMode(false);
    setShowForm(true);
  };

  const openEditForm = (override: AddressThresholdOverride) => {
    setFormAddress(override.address);
    setFormThreshold(String(override.threshold_usd));
    setFormNote(override.note || '');
    setFormError(null);
    setEditMode(true);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    const address = formAddress.trim().toLowerCase();
    if (!/^0x[0-9a-f]{40}$/i.test(address)) {
      setFormError('Invalid address format (must be 0x + 40 hex chars)');
      return;
    }

    const threshold = parseFloat(formThreshold);
    if (isNaN(threshold) || threshold < 0) {
      setFormError('Threshold must be >= 0');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      await complianceApi.addressThresholds.upsert(orgId, address, {
        threshold_usd: threshold,
        note: formNote.trim() || undefined,
      });
      setShowForm(false);
      loadOverrides(editMode ? offset : 0);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to save threshold override');
    } finally {
      setFormSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!orgId || !deleteTarget) return;
    try {
      await complianceApi.addressThresholds.delete(orgId, deleteTarget.address);
      setDeleteTarget(null);
      loadOverrides();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to delete threshold override');
      setDeleteTarget(null);
    }
  };

  if (!orgId) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-[#6B7280]">
            Per-address threshold overrides. When set, the address-specific threshold takes precedence
            over the org-level threshold. Use $0 to require travel rule data for every transfer involving this address.
          </p>
        </div>
        <Button onClick={openCreateForm} size="sm" className="gap-2 shrink-0">
          <Plus className="w-4 h-4" />
          Add Override
        </Button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-8">
          <Loader2 className="w-6 h-6 animate-spin text-[#6B7280]" />
        </div>
      ) : overrides.length === 0 ? (
        <div className="text-center py-8">
          <MapPin className="w-8 h-8 mx-auto mb-2 text-[#94A3B8]" />
          <p className="text-[#6B7280]">No address threshold overrides</p>
          <p className="text-[#94A3B8] text-sm mt-1">
            All addresses use the org-level threshold
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Threshold (USD)</TableHead>
                <TableHead>Note</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="w-[80px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {overrides.map((o) => (
                <TableRow key={o.id}>
                  <TableCell className="font-mono text-xs">{o.address}</TableCell>
                  <TableCell>
                    {o.threshold_usd === 0 ? (
                      <span className="text-[#DC2626] font-medium">$0 (all transfers)</span>
                    ) : (
                      <span>${o.threshold_usd.toLocaleString(undefined, { minimumFractionDigits: 2 })}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-[#6B7280] max-w-[200px] truncate">
                    {o.note || '-'}
                  </TableCell>
                  <TableCell className="text-xs text-[#6B7280]">
                    {new Date(o.updated_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => openEditForm(o)}
                        className="h-7 w-7 p-0"
                      >
                        <Pencil className="w-3.5 h-3.5 text-[#6B7280]" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeleteTarget(o)}
                        className="h-7 w-7 p-0 text-[#DC2626] hover:text-[#991B1B]"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {total > PAGE_SIZE && (
            <Pagination
              total={total}
              limit={PAGE_SIZE}
              offset={offset}
              onPageChange={loadOverrides}
            />
          )}
        </>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editMode ? 'Edit' : 'Add'} Address Threshold Override</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1">
                Address
              </label>
              <Input
                value={formAddress}
                onChange={(e) => setFormAddress(e.target.value)}
                placeholder="0x..."
                disabled={editMode}
                className="font-mono text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1">
                Threshold (USD)
              </label>
              <Input
                type="number"
                value={formThreshold}
                onChange={(e) => setFormThreshold(e.target.value)}
                placeholder="0"
                min="0"
                step="0.01"
              />
              <p className="text-xs text-[#6B7280] mt-1">
                Set to $0 to require travel rule data for every transfer involving this address.
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1">
                Note (optional)
              </label>
              <Input
                value={formNote}
                onChange={(e) => setFormNote(e.target.value)}
                placeholder="e.g., High-risk counterparty"
              />
            </div>
            {formError && (
              <p className="text-sm text-[#DC2626]">{formError}</p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {editMode ? 'Save' : 'Add Override'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete Threshold Override"
        description={`Remove the threshold override for ${deleteTarget?.address}? This address will revert to the org-level threshold.`}
        onConfirm={handleDelete}
        confirmLabel="Delete"
        variant="destructive"
      />
    </div>
  );
}
