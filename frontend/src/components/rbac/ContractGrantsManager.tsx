import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract, ContractGrant, Group } from '@/types/rbac';
import { CLAIM_LABELS } from '@/types/rbac';
import ContractGrantForm from './ContractGrantForm';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  Loader2,
  Plus,
  Pencil,
  Trash2,
  Shield,
  Users,
  FileCode2,
  Copy,
  Check,
  X,
} from 'lucide-react';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};

interface ContractGrantsManagerProps {
  orgId: string;
  contract: Contract;
  onClose: () => void;
}

// Extended grant type that includes the group info
interface GrantWithGroup extends ContractGrant {
  group?: Group;
}

export default function ContractGrantsManager({
  orgId,
  contract,
  onClose,
}: ContractGrantsManagerProps) {
  const [grants, setGrants] = useState<GrantWithGroup[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<ContractGrant | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<GrantWithGroup | null>(null);
  const [copiedAddress, setCopiedAddress] = useState(false);

  const contractAddress = getContractAddress(contract);

  useEffect(() => {
    loadData();
  }, [orgId, contractAddress]);

  const loadData = async () => {
    try {
      setLoading(true);
      // Load grants and groups in parallel
      const [grantsRes, groupsRes] = await Promise.all([
        rbacApi.contracts.listGrants(orgId, contractAddress),
        rbacApi.groups.list(orgId),
      ]);

      const grantsData = grantsRes.data || [];
      const groupsData = groupsRes.data || [];
      setGroups(groupsData);

      // Map group info to grants
      const grantsWithGroups: GrantWithGroup[] = grantsData.map(grant => ({
        ...grant,
        group: groupsData.find(g => g.id === grant.group_id),
      }));

      setGrants(grantsWithGroups);
    } catch (error) {
      console.error('Failed to load grants:', error);
      setGrants([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadData();
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;

    try {
      await rbacApi.contracts.deleteGrant(orgId, contractAddress, deleteTarget.group_id);
      setDeleteTarget(null);
      await loadData();
    } catch (error) {
      console.error('Failed to delete grant:', error);
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(contractAddress);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const truncateAddress = (address: string | undefined) => {
    if (!address) return '-';
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  const existingGrantGroupIds = grants.map(g => g.group_id);

  return (
    <div className="space-y-4">
      {/* Contract header */}
      <div className="flex items-start justify-between pb-4 border-b border-[#E5E7EB]">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#F5F3FF] flex items-center justify-center">
            <FileCode2 className="w-5 h-5 text-[#8950FA]" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-[#0F0F0F]">
              {contract.name || 'Unnamed Contract'}
            </h3>
            <div className="flex items-center gap-2 mt-1">
              <span className="font-mono text-sm text-[#6B7280]" title={contractAddress}>
                {truncateAddress(contractAddress)}
              </span>
              <button
                onClick={copyToClipboard}
                className="p-1 rounded hover:bg-[#F1F5F9] text-[#94A3B8] hover:text-[#6B7280] transition-colors"
                title="Copy address"
              >
                {copiedAddress ? (
                  <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="w-4 h-4" />
        </Button>
      </div>

      {/* Grants section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#8950FA]" />
            <span className="text-sm font-medium text-[#374151]">Group Permissions</span>
          </div>
          <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
            <Plus className="w-4 h-4" />
            Add Grant
          </Button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-[#94A3B8] animate-spin" />
          </div>
        ) : grants.length === 0 ? (
          <div className="text-center py-8 border border-dashed border-[#E5E7EB] rounded-lg">
            <Users className="w-8 h-8 text-[#94A3B8] mx-auto mb-2" />
            <p className="text-sm text-[#6B7280] mb-3">
              No groups have permissions on this contract
            </p>
            <Button variant="outline" size="sm" onClick={() => setShowForm(true)} className="gap-2">
              <Plus className="w-4 h-4" />
              Add a grant
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            {grants.map(grant => (
              <div
                key={grant.id}
                className="p-4 border border-[#E5E7EB] rounded-lg hover:border-[#DDD6FE] transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-lg bg-[#F1F5F9] flex items-center justify-center">
                      <Users className="w-4 h-4 text-[#6B7280]" />
                    </div>
                    <div>
                      <h4 className="font-medium text-[#0F0F0F]">
                        {grant.group?.name || 'Unknown Group'}
                      </h4>
                      {grant.group && (
                        <p className="text-xs text-[#94A3B8] mt-0.5">
                          {grant.group.path}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(grant)}
                      title="Edit grant"
                    >
                      <Pencil className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteTarget(grant)}
                      className="text-[#991B1B] hover:text-[#7F1D1D] hover:bg-[#FEE2E2]"
                      title="Delete grant"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                {/* Claims badges */}
                <div className="mt-3 flex flex-wrap gap-2">
                  <span className="text-xs text-[#6B7280]">Claims:</span>
                  {grant.claims.map(claim => (
                    <span
                      key={claim}
                      className="px-2 py-0.5 rounded-full text-xs font-medium bg-[#F5F3FF] text-[#8950FA]"
                    >
                      {CLAIM_LABELS[claim]}
                    </span>
                  ))}
                </div>

                {/* Functions */}
                <div className="mt-2 text-xs text-[#6B7280]">
                  Functions:{' '}
                  {!grant.functions || grant.functions.length === 0 ? (
                    <span className="text-[#22C55E]">All allowed</span>
                  ) : (
                    <span className="font-mono">
                      {grant.functions.slice(0, 3).join(', ')}
                      {grant.functions.length > 3 && ` +${grant.functions.length - 3} more`}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Grant Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-md max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Permission Grant</DialogTitle>
          </DialogHeader>
          <ContractGrantForm
            orgId={orgId}
            contractAddress={contractAddress}
            groups={groups}
            existingGrantGroupIds={existingGrantGroupIds}
            onClose={() => setShowForm(false)}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Grant Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-md max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Permission Grant</DialogTitle>
          </DialogHeader>
          {editing && (
            <ContractGrantForm
              key={editing.id}
              orgId={orgId}
              contractAddress={contractAddress}
              grant={editing}
              groups={groups}
              existingGrantGroupIds={existingGrantGroupIds}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Grant"
        description={`Are you sure you want to remove "${deleteTarget?.group?.name || 'this group'}" permissions from this contract?`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={handleDeleteConfirm}
        variant="destructive"
      />
    </div>
  );
}
