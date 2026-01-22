import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract } from '@/types/rbac';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};
import ContractForm from './ContractForm';
import { useOrgContext } from './RBACManager';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FileCode2, Plus, Pencil, Trash2, Loader2 } from 'lucide-react';

export default function ContractList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Contract | null>(null);

  useEffect(() => {
    if (orgId) {
      loadContracts();
    }
  }, [orgId]);

  const loadContracts = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      const response = await rbacApi.contracts.list(orgId);
      setContracts(response.data || []);
    } catch (error) {
      console.error('Failed to load contracts:', error);
      setContracts([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (contract: Contract) => {
    const addr = getContractAddress(contract);
    if (
      !confirm(
        `Delete contract "${contract.name || addr}"? This cannot be undone.`
      )
    )
      return;

    try {
      await rbacApi.contracts.delete(orgId, addr);
      await loadContracts();
    } catch (error) {
      console.error('Failed to delete contract:', error);
      alert('Failed to delete contract.');
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadContracts();
  };

  const truncateAddress = (address: string | undefined) => {
    if (!address) return '-';
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-[#374151]">Contracts</h3>
          <p className="text-xs text-[#6B7280] mt-0.5">
            Registered contracts with access grants for groups
          </p>
        </div>
        <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
          <Plus className="w-4 h-4" />
          Add Contract
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-[#94A3B8] animate-spin" />
        </div>
      ) : contracts.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <FileCode2 className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-4">No contracts registered</p>
          <Button
            variant="outline"
            onClick={() => setShowForm(true)}
            className="gap-2"
          >
            <Plus className="w-4 h-4" />
            Register your first contract
          </Button>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Address</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {contracts.map((contract, index) => (
              <TableRow
                key={contract.id}
                className="animate-fade-in"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <FileCode2 className="w-4 h-4 text-[#8950FA]" />
                    <span
                      className="font-mono text-sm"
                      title={getContractAddress(contract)}
                    >
                      {truncateAddress(getContractAddress(contract))}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <span className="text-sm">{contract.name || '-'}</span>
                </TableCell>
                <TableCell>
                  <span className="text-sm text-[#6B7280]">
                    {formatDate(contract.created_at)}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(contract)}
                      title="Edit contract"
                    >
                      <Pencil className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(contract)}
                      className="text-[#991B1B] hover:text-[#7F1D1D] hover:bg-[#FEE2E2]"
                      title="Delete contract"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* Create Contract Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Register Contract</DialogTitle>
          </DialogHeader>
          <ContractForm
            orgId={orgId}
            onClose={() => setShowForm(false)}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Contract Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Contract</DialogTitle>
          </DialogHeader>
          {editing && (
            <ContractForm
              key={editing.id}
              orgId={orgId}
              contract={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
