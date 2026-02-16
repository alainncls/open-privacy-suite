import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import Pagination from '@/components/ui/Pagination';
import { Loader2, Plus, AlertCircle, FileText } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import type { TravelRuleRecord, TransferType } from '@/types/compliance';

const PAGE_SIZE = 25;

function getRecordStatus(record: TravelRuleRecord): 'unused' | 'used' | 'expired' {
  if (record.used_at) return 'used';
  if (new Date(record.expires_at) < new Date()) return 'expired';
  return 'unused';
}

const statusBadgeVariant: Record<string, 'success' | 'secondary' | 'destructive'> = {
  unused: 'success',
  used: 'secondary',
  expired: 'destructive',
};

export default function TravelRuleRecordList() {
  const { selectedOrg } = useComplianceOrgContext();
  const orgId = selectedOrg?.id;

  const [records, setRecords] = useState<TravelRuleRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  // Form state
  const [formOriginatorUserId, setFormOriginatorUserId] = useState('');
  const [formOriginatorData, setFormOriginatorData] = useState('{}');
  const [formBeneficiaryData, setFormBeneficiaryData] = useState('{}');
  const [formTransferType, setFormTransferType] = useState<TransferType>('eth');
  const [formTokenAddress, setFormTokenAddress] = useState('');
  const [formBeneficiaryAddress, setFormBeneficiaryAddress] = useState('');
  const [formAmountWei, setFormAmountWei] = useState('');
  const [formAmountUsd, setFormAmountUsd] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);

  const loadRecords = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.travelRules.list(orgId, { limit: PAGE_SIZE, offset: newOffset });
      const page = response.data;
      setRecords(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setRecords([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load travel rule records');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setOffset(0);
    loadRecords(0);
  }, [orgId]);

  const openCreateForm = () => {
    setFormOriginatorUserId('');
    setFormOriginatorData('{}');
    setFormBeneficiaryData('{}');
    setFormTransferType('eth');
    setFormTokenAddress('');
    setFormBeneficiaryAddress('');
    setFormAmountWei('');
    setFormAmountUsd('');
    setFormError(null);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    let originatorData: Record<string, unknown>;
    let beneficiaryData: Record<string, unknown>;
    try {
      originatorData = JSON.parse(formOriginatorData);
    } catch {
      setFormError('Originator data must be valid JSON');
      return;
    }
    try {
      beneficiaryData = JSON.parse(formBeneficiaryData);
    } catch {
      setFormError('Beneficiary data must be valid JSON');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      await complianceApi.travelRules.create(orgId, {
        originator_user_id: formOriginatorUserId.trim(),
        originator_data: originatorData,
        beneficiary_data: beneficiaryData,
        transfer_type: formTransferType,
        token_address: formTransferType === 'erc20' ? formTokenAddress.trim().toLowerCase() : undefined,
        beneficiary_address: formBeneficiaryAddress.trim().toLowerCase(),
        amount_wei: formAmountWei.trim(),
        amount_usd: parseFloat(formAmountUsd) || 0,
      });
      setShowForm(false);
      loadRecords(0);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to create travel rule record');
    } finally {
      setFormSaving(false);
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
        <h3 className="text-base font-medium text-[#374151]">Travel Rule Records</h3>
        <Button size="sm" onClick={openCreateForm}>
          <Plus className="w-4 h-4 mr-1" />
          Create Record
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {records.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <FileText className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-2">No travel rule records</p>
          <p className="text-[#94A3B8] text-sm">
            Create a travel rule record to authorize high-value transfers
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Originator</TableHead>
                <TableHead>Beneficiary</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Amount (USD)</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {records.map(record => {
                const status = getRecordStatus(record);
                return (
                  <TableRow key={record.id}>
                    <TableCell className="font-mono text-xs text-[#6B7280]">
                      {record.originator_user_id.slice(0, 8)}...
                    </TableCell>
                    <TableCell className="font-mono text-xs text-[#6B7280]">
                      {record.beneficiary_address.slice(0, 10)}...{record.beneficiary_address.slice(-6)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{record.transfer_type.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell>${record.amount_usd.toLocaleString()}</TableCell>
                    <TableCell>
                      <Badge variant={statusBadgeVariant[status]}>{status}</Badge>
                    </TableCell>
                    <TableCell className="text-[#6B7280] text-sm">
                      {new Date(record.created_at).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            limit={PAGE_SIZE}
            offset={offset}
            onPageChange={newOffset => loadRecords(newOffset)}
          />
        </>
      )}

      {/* Create Dialog */}
      <Dialog open={showForm} onOpenChange={open => { if (!open) setShowForm(false); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Travel Rule Record</DialogTitle>
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
                Originator User ID
              </label>
              <Input
                value={formOriginatorUserId}
                onChange={e => setFormOriginatorUserId(e.target.value)}
                placeholder="UUID of the originating user"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Originator Data (JSON)
                </label>
                <Textarea
                  value={formOriginatorData}
                  onChange={e => setFormOriginatorData(e.target.value)}
                  placeholder='{"name": "..."}'
                  rows={3}
                  className="font-mono text-xs"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Beneficiary Data (JSON)
                </label>
                <Textarea
                  value={formBeneficiaryData}
                  onChange={e => setFormBeneficiaryData(e.target.value)}
                  placeholder='{"name": "..."}'
                  rows={3}
                  className="font-mono text-xs"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Transfer Type
                </label>
                <Select value={formTransferType} onValueChange={v => setFormTransferType(v as TransferType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="eth">ETH (Native)</SelectItem>
                    <SelectItem value="erc20">ERC-20 Token</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {formTransferType === 'erc20' && (
                <div>
                  <label className="block text-sm font-medium text-[#374151] mb-1.5">
                    Token Address
                  </label>
                  <Input
                    value={formTokenAddress}
                    onChange={e => setFormTokenAddress(e.target.value)}
                    placeholder="0x..."
                  />
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Beneficiary Address
              </label>
              <Input
                value={formBeneficiaryAddress}
                onChange={e => setFormBeneficiaryAddress(e.target.value)}
                placeholder="0x..."
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Amount (Wei)
                </label>
                <Input
                  value={formAmountWei}
                  onChange={e => setFormAmountWei(e.target.value)}
                  placeholder="1000000000000000000"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Amount (USD)
                </label>
                <Input
                  type="number"
                  value={formAmountUsd}
                  onChange={e => setFormAmountUsd(e.target.value)}
                  placeholder="2500.00"
                  min="0"
                  step="0.01"
                  required
                />
              </div>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Create Record
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
