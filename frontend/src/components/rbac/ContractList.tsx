import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { ContractOwnership, Group } from '@/types/rbac';
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
import { FileCode2, Plus, Pencil, Trash2, Loader2, FolderTree } from 'lucide-react';

export default function ContractList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [contracts, setContracts] = useState<ContractOwnership[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<ContractOwnership | null>(null);

  useEffect(() => {
    if (orgId) {
      loadData();
    }
  }, [orgId]);

  const loadData = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      const [contractsRes, groupsRes] = await Promise.all([
        rbacApi.contracts.list(orgId),
        rbacApi.groups.list(orgId),
      ]);
      setContracts(contractsRes.data || []);
      setGroups(groupsRes.data || []);
    } catch (error) {
      console.error('Failed to load contracts:', error);
      setContracts([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (contract: ContractOwnership) => {
    if (
      !confirm(
        `Delete contract ownership for ${contract.contract_address}? This cannot be undone.`
      )
    )
      return;

    try {
      await rbacApi.contracts.delete(orgId, contract.contract_address);
      await loadData();
    } catch (error) {
      console.error('Failed to delete contract:', error);
      alert('Failed to delete contract ownership.');
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadData();
  };

  const getGroupName = (groupId: string) => {
    const group = groups.find(g => g.id === groupId);
    return group ? group.name : groupId;
  };

  const getGroupPath = (groupId: string) => {
    const group = groups.find(g => g.id === groupId);
    return group ? group.path : '';
  };

  const truncateAddress = (address: string) => {
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-white/80">Contract Ownership</h3>
          <p className="text-xs text-white/50 mt-0.5">
            Track deployed contracts and their owner groups
          </p>
        </div>
        <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
          <Plus className="w-4 h-4" />
          Add Contract
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-white/40 animate-spin" />
        </div>
      ) : contracts.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
            <FileCode2 className="w-8 h-8 text-white/30" />
          </div>
          <p className="text-white/50 mb-4">No contracts registered</p>
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
              <TableHead>Contract Address</TableHead>
              <TableHead>Owner Group</TableHead>
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
                    <FileCode2 className="w-4 h-4 text-primary-400" />
                    <span
                      className="font-mono text-sm"
                      title={contract.contract_address}
                    >
                      {truncateAddress(contract.contract_address)}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <FolderTree className="w-4 h-4 text-white/40" />
                    <span className="text-sm">{getGroupName(contract.owner_group_id)}</span>
                    <span className="text-xs text-white/40 font-mono">
                      ({getGroupPath(contract.owner_group_id)})
                    </span>
                  </div>
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
                      className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
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
            groups={groups}
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
              groups={groups}
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
