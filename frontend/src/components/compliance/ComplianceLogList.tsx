import { useState, useEffect } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import Pagination from '@/components/ui/Pagination';
import { Loader2, AlertCircle, ScrollText } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import type { ComplianceLog, Decision, TransferType } from '@/types/compliance';

const PAGE_SIZE = 25;

export default function ComplianceLogList() {
  const { selectedOrg } = useComplianceOrgContext();
  const orgId = selectedOrg?.id;

  const [logs, setLogs] = useState<ComplianceLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterDecision, setFilterDecision] = useState<string>('');
  const [filterTransferType, setFilterTransferType] = useState<string>('');
  const [filterUserId, setFilterUserId] = useState('');
  const [debouncedUserId, setDebouncedUserId] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedUserId(filterUserId), 300);
    return () => clearTimeout(timer);
  }, [filterUserId]);

  const loadLogs = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.logs.list(orgId, {
        limit: PAGE_SIZE,
        offset: newOffset,
        decision: (filterDecision && filterDecision !== 'all' ? filterDecision as Decision : undefined),
        transfer_type: (filterTransferType && filterTransferType !== 'all' ? filterTransferType as TransferType : undefined),
        user_id: debouncedUserId || undefined,
      });
      const page = response.data;
      setLogs(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setLogs([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load compliance logs');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setOffset(0);
    loadLogs(0);
  }, [orgId, filterDecision, filterTransferType, debouncedUserId]);

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
        <h3 className="text-base font-medium text-[#374151]">Compliance Logs</h3>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={filterDecision || 'all'} onValueChange={v => setFilterDecision(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="All decisions" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All decisions</SelectItem>
            <SelectItem value="allowed">Allowed</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
          </SelectContent>
        </Select>

        <Select value={filterTransferType || 'all'} onValueChange={v => setFilterTransferType(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="eth">ETH</SelectItem>
            <SelectItem value="erc20">ERC-20</SelectItem>
          </SelectContent>
        </Select>

        <Input
          value={filterUserId}
          onChange={e => setFilterUserId(e.target.value)}
          placeholder="Filter by user ID..."
          className="max-w-[250px]"
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEE2E2] border border-[#FECACA] text-[#991B1B] text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {logs.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <ScrollText className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-2">No compliance logs</p>
          <p className="text-[#94A3B8] text-sm">
            Compliance decisions will appear here when transfers are evaluated
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>From → To</TableHead>
                <TableHead>Amount (USD)</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead>Reason</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map(log => (
                <TableRow key={log.id}>
                  <TableCell className="text-[#6B7280] text-xs whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-[#6B7280]">
                    {log.user_id.slice(0, 8)}...
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{log.transfer_type.toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-[#6B7280]">
                    {log.from_address.slice(0, 6)}...→{log.to_address.slice(0, 6)}...
                  </TableCell>
                  <TableCell>
                    {log.amount_usd != null ? `$${log.amount_usd.toLocaleString()}` : '—'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={log.decision === 'allowed' ? 'success' : 'destructive'}>
                      {log.decision}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-[#6B7280] text-sm max-w-[200px] truncate">
                    {log.denial_reason || '—'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            limit={PAGE_SIZE}
            offset={offset}
            onPageChange={newOffset => loadLogs(newOffset)}
          />
        </>
      )}
    </div>
  );
}
