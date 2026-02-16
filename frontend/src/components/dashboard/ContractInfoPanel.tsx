import { useState, useEffect, useRef } from 'react';
import { Badge } from '@/components/ui/badge';
import { testApi } from '@/api/client';
import { CLAIM_LABELS, type Claim } from '@/types/rbac';
import { Loader2, FileText, AlertTriangle } from 'lucide-react';

function getClaimColor(claim: string): string {
  switch (claim) {
    case 'admin': return 'bg-red-100 text-[#991B1B] border-red-300';
    case 'deployer': return 'bg-purple-100 text-purple-700 border-purple-300';
    case 'upgrade': return 'bg-orange-100 text-orange-700 border-orange-300';
    case 'writer': return 'bg-blue-100 text-blue-700 border-blue-300';
    case 'reader': return 'bg-green-100 text-green-700 border-green-300';
    default: return 'bg-gray-100 text-gray-600 border-gray-300';
  }
}

const ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;

interface ContractLookupResult {
  contract: { id: string; name: string; address: string; org_id: string };
  organization: { id: string; name: string; slug: string };
  grants: Array<{
    grant: { id: string; contract_id: string; group_id: string; functions: Array<{ selector: string }> | null };
    group: { id: string; name: string; path: string };
    access: { claims: string[]; allowed_methods: string[] } | null;
  }>;
}

interface ContractInfoPanelProps {
  contractAddress: string;
}

export function ContractInfoPanel({ contractAddress }: ContractInfoPanelProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ContractLookupResult | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastAddress = useRef<string>('');

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    const addr = contractAddress.trim().toLowerCase();

    if (!ADDRESS_REGEX.test(addr)) {
      setData(null);
      setError(null);
      lastAddress.current = '';
      return;
    }

    if (addr === lastAddress.current && data) return;

    debounceRef.current = setTimeout(async () => {
      lastAddress.current = addr;
      setLoading(true);
      setError(null);
      try {
        const result = await testApi.lookupContract(addr);
        setData(result);
      } catch (err: unknown) {
        const axiosError = err as { response?: { status?: number } };
        if (axiosError?.response?.status === 404) {
          setError('Contract not registered');
        } else {
          setError('Failed to look up contract');
        }
        setData(null);
      } finally {
        setLoading(false);
      }
    }, 500);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [contractAddress]);

  if (!ADDRESS_REGEX.test(contractAddress.trim().toLowerCase())) return null;

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-3 rounded-lg bg-[#F0F9FF] border border-[#BAE6FD] text-sm text-[#6B7280]">
        <Loader2 className="w-4 h-4 animate-spin" />
        Looking up contract...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 p-3 rounded-lg bg-[#FEF9C3] border border-[#FDE047] text-sm text-[#854D0E]" data-testid="contract-info-panel">
        <AlertTriangle className="w-4 h-4" />
        {error}
      </div>
    );
  }

  if (!data) return null;

  const { contract, organization, grants } = data;

  return (
    <div className="p-3 rounded-lg bg-[#F0F9FF] border border-[#BAE6FD] space-y-3 animate-fade-in" data-testid="contract-info-panel">
      {/* Header */}
      <div className="flex items-center gap-2">
        <FileText className="w-4 h-4 text-blue-600" />
        <span className="text-sm font-medium text-[#374151]">
          {contract.name || 'Unnamed Contract'}
        </span>
        <span className="text-xs text-[#94A3B8]">&middot;</span>
        <span className="text-xs text-[#6B7280]">{organization.name}</span>
      </div>

      {/* Groups with access */}
      {grants.length > 0 ? (
        <div>
          <div className="text-xs font-medium text-[#6B7280] mb-1.5">Groups with access</div>
          <div className="space-y-1">
            {grants.map((g) => {
              const claims = g.access?.claims || [];
              const hasFunctionRestrictions = g.grant.functions !== null && g.grant.functions !== undefined;

              return (
                <div key={g.grant.id} className="flex items-center gap-2 text-sm">
                  <span className="text-[#374151]">{g.group.name}</span>
                  <span className="text-[#94A3B8]">&mdash;</span>
                  {claims.length > 0 ? (
                    <div className="flex gap-1">
                      {claims.map((claim) => (
                        <Badge
                          key={claim}
                          variant="outline"
                          className={`text-xs py-0 ${getClaimColor(claim)}`}
                        >
                          {CLAIM_LABELS[claim as Claim] || claim}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-[#94A3B8]">No claims</span>
                  )}
                  {hasFunctionRestrictions && (
                    <span className="text-xs text-[#94A3B8]">
                      ({g.grant.functions!.length} function{g.grant.functions!.length !== 1 ? 's' : ''})
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="text-xs text-[#94A3B8]">No groups have been granted access</div>
      )}
    </div>
  );
}
