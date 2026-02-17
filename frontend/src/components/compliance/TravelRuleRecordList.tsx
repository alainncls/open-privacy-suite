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
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import Pagination from '@/components/ui/Pagination';
import { Loader2, Plus, AlertCircle, FileText } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { UserSearchInput } from './UserSearchInput';
import type { TravelRuleRecord, TransferType, TokenPrice } from '@/types/compliance';

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

function isValidAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

function humanToWei(amount: string, decimals: number): string {
  if (!amount || isNaN(parseFloat(amount))) return '';
  const parts = amount.split('.');
  const whole = parts[0] || '0';
  const fraction = (parts[1] || '').padEnd(decimals, '0').slice(0, decimals);
  const combined = whole + fraction;
  // Remove leading zeros
  return combined.replace(/^0+/, '') || '0';
}

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
  const [formOriginatorName, setFormOriginatorName] = useState('');
  const [formOriginatorAccountRef, setFormOriginatorAccountRef] = useState('');
  const [formBeneficiaryName, setFormBeneficiaryName] = useState('');
  const [formBeneficiaryInstitution, setFormBeneficiaryInstitution] = useState('');
  const [formTransferType, setFormTransferType] = useState<TransferType>('eth');
  const [formTokenAddress, setFormTokenAddress] = useState('');
  const [formBeneficiaryAddress, setFormBeneficiaryAddress] = useState('');
  const [formHumanAmount, setFormHumanAmount] = useState('');
  const [formAmountUsd, setFormAmountUsd] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);
  const [addressError, setAddressError] = useState('');
  const [availableTokens, setAvailableTokens] = useState<TokenPrice[]>([]);

  const selectedTokenInfo = formTransferType === 'eth'
    ? availableTokens.find(t => t.token_address === 'native')
    : availableTokens.find(t => t.token_address === formTokenAddress);

  const erc20Tokens = availableTokens.filter(t => t.token_address !== 'native');

  useEffect(() => {
    if (selectedTokenInfo && formHumanAmount && !isNaN(parseFloat(formHumanAmount))) {
      const usd = parseFloat(formHumanAmount) * selectedTokenInfo.price_usd;
      setFormAmountUsd(usd.toFixed(2));
    }
  }, [formHumanAmount, selectedTokenInfo]);

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

  const openCreateForm = async () => {
    setFormOriginatorUserId('');
    setFormOriginatorName('');
    setFormOriginatorAccountRef('');
    setFormBeneficiaryName('');
    setFormBeneficiaryInstitution('');
    setFormTransferType('eth');
    setFormTokenAddress('');
    setFormBeneficiaryAddress('');
    setFormHumanAmount('');
    setFormAmountUsd('');
    setAddressError('');
    setFormError(null);
    setShowForm(true);
    // Fetch available tokens for the org
    try {
      const response = await complianceApi.tokens.list(orgId!);
      setAvailableTokens(response.data.data || []);
    } catch {
      setAvailableTokens([]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    if (formBeneficiaryAddress && !isValidAddress(formBeneficiaryAddress)) {
      setAddressError('Invalid address format. Must be 0x followed by 40 hex characters.');
      return;
    }

    const originatorData = {
      name: formOriginatorName.trim(),
      ...(formOriginatorAccountRef.trim() && { account_ref: formOriginatorAccountRef.trim() }),
    };
    const beneficiaryData = {
      name: formBeneficiaryName.trim(),
      ...(formBeneficiaryInstitution.trim() && { institution: formBeneficiaryInstitution.trim() }),
    };

    const amountWei = selectedTokenInfo
      ? humanToWei(formHumanAmount, selectedTokenInfo.decimals)
      : formHumanAmount; // fallback: user enters wei directly if no token config
    const amountUsd = parseFloat(formAmountUsd) || 0;

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
        amount_wei: amountWei,
        amount_usd: amountUsd,
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
                Originator
              </label>
              <UserSearchInput orgId={orgId!} value={formOriginatorUserId} onChange={setFormOriginatorUserId} />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Originator Name <span className="text-[#991B1B]">*</span>
                </label>
                <Input
                  value={formOriginatorName}
                  onChange={e => setFormOriginatorName(e.target.value)}
                  placeholder="Full legal name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Account Reference
                </label>
                <Input
                  value={formOriginatorAccountRef}
                  onChange={e => setFormOriginatorAccountRef(e.target.value)}
                  placeholder="Optional account ref"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Beneficiary Name <span className="text-[#991B1B]">*</span>
                </label>
                <Input
                  value={formBeneficiaryName}
                  onChange={e => setFormBeneficiaryName(e.target.value)}
                  placeholder="Full legal name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Institution
                </label>
                <Input
                  value={formBeneficiaryInstitution}
                  onChange={e => setFormBeneficiaryInstitution(e.target.value)}
                  placeholder="Optional institution"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#374151] mb-1.5">
                  Transfer Type
                </label>
                <Select value={formTransferType} onValueChange={v => { setFormTransferType(v as TransferType); setFormTokenAddress(''); }}>
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
                    Token
                  </label>
                  {erc20Tokens.length > 0 ? (
                    <Select value={formTokenAddress} onValueChange={setFormTokenAddress}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select token" />
                      </SelectTrigger>
                      <SelectContent>
                        {erc20Tokens.map(token => (
                          <SelectItem key={token.token_address} value={token.token_address}>
                            {token.symbol} ({token.token_address.slice(0, 6)}...{token.token_address.slice(-4)})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <p className="text-xs text-[#6B7280] mt-2">
                      No ERC-20 tokens configured. Add them in Token Prices tab.
                    </p>
                  )}
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-[#374151] mb-1.5">
                Beneficiary Address
              </label>
              <Input
                value={formBeneficiaryAddress}
                onChange={e => { setFormBeneficiaryAddress(e.target.value); setAddressError(''); }}
                onBlur={() => {
                  if (formBeneficiaryAddress && !isValidAddress(formBeneficiaryAddress)) {
                    setAddressError('Invalid address format. Must be 0x followed by 40 hex characters.');
                  } else {
                    setAddressError('');
                  }
                }}
                placeholder="0x..."
                required
              />
              {addressError && <p className="text-xs text-[#991B1B] mt-1">{addressError}</p>}
            </div>

            <div>
              {selectedTokenInfo ? (
                <>
                  <label className="block text-sm font-medium text-[#374151] mb-1.5">
                    Amount ({selectedTokenInfo.symbol})
                  </label>
                  <Input
                    value={formHumanAmount}
                    onChange={e => setFormHumanAmount(e.target.value)}
                    placeholder="1.5"
                    required
                  />
                  {formHumanAmount && !isNaN(parseFloat(formHumanAmount)) && (
                    <p className="text-xs text-[#6B7280] mt-1">
                      ≈ {humanToWei(formHumanAmount, selectedTokenInfo.decimals)} wei | ≈ ${formAmountUsd} USD
                    </p>
                  )}
                </>
              ) : (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEF3C7] border border-[#FDE68A] text-[#92400E] text-sm">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  Configure token prices in the Token Prices tab first to enable amount entry.
                </div>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving || !selectedTokenInfo}>
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
