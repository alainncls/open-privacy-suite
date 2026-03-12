import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract, ContractSyncCheckResponse, ContractSyncStatus } from '@/types/rbac';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};
import ContractForm from './ContractForm';
import ContractGrantsManager from './ContractGrantsManager';
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
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import { FileCode2, Plus, Pencil, Trash2, Loader2, Copy, Check, RefreshCw, AlertTriangle, Shield } from 'lucide-react';

const PAGE_SIZE = 25;

export default function ContractList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Contract | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Contract | null>(null);
  const [showDeleteError, setShowDeleteError] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [managingGrants, setManagingGrants] = useState<Contract | null>(null);
  const [grantSummary, setGrantSummary] = useState<Record<string, { count: number; groups: Array<{id: string; name: string}> }>>({});

  // Sync with chain state
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<ContractSyncCheckResponse | null>(null);
  const [showSyncDialog, setShowSyncDialog] = useState(false);
  const [deletingStale, setDeletingStale] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  useEffect(() => {
    if (orgId) {
      loadContracts(0);
    }
  }, [orgId]);

  const loadContracts = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      const response = await rbacApi.contracts.list(orgId, { limit: PAGE_SIZE, offset: newOffset });
      const page = response.data;
      setContracts(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
      try {
        const summaryRes = await rbacApi.contracts.grantSummary(orgId);
        setGrantSummary(summaryRes.data || {});
      } catch {
        setGrantSummary({});
      }
    } catch (error) {
      console.error('Failed to load contracts:', error);
      setContracts([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    const addr = getContractAddress(deleteTarget);

    try {
      await rbacApi.contracts.delete(orgId, addr);
      setDeleteTarget(null);
      await loadContracts();
    } catch (error) {
      console.error('Failed to delete contract:', error);
      setDeleteTarget(null);
      setShowDeleteError(true);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadContracts();
  };

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Sync with chain - check contracts exist on-chain
  const handleSyncCheck = async () => {
    if (!orgId) return;
    try {
      setSyncing(true);
      setSyncError(null);
      const response = await rbacApi.contracts.syncCheck(orgId);
      setSyncResult(response.data);

      // Always show the dialog with results
      setShowSyncDialog(true);
    } catch (error) {
      console.error('Failed to sync contracts:', error);
      setSyncError('Failed to check contracts against chain');
    } finally {
      setSyncing(false);
    }
  };

  // Delete stale (missing) contracts
  const handleDeleteStale = async () => {
    if (!orgId || !syncResult || !syncResult.missing?.length) return;

    try {
      setDeletingStale(true);
      const contractIds = syncResult.missing.map(c => c.id);
      await rbacApi.contracts.syncDelete(orgId, contractIds);
      setShowSyncDialog(false);
      setSyncResult(null);
      await loadContracts();
    } catch (error) {
      console.error('Failed to delete stale contracts:', error);
      setSyncError('Failed to delete stale contracts');
    } finally {
      setDeletingStale(false);
    }
  };

  const truncateAddress = (address: string | undefined) => {
    if (!address) return '-';
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Contracts</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Registered contracts with access grants for groups
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={handleSyncCheck}
            size="sm"
            variant="outline"
            className="gap-2"
            disabled={syncing || contracts.length === 0}
          >
            <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
            {syncing ? 'Checking...' : 'Sync with Chain'}
          </Button>
          <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
            <Plus className="w-4 h-4" />
            Add Contract
          </Button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : contracts.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <FileCode2 className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-4">No contracts registered</p>
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
              <TableHead className="text-center w-16">ABI</TableHead>
              <TableHead className="text-center w-20">Groups</TableHead>
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
                    <FileCode2 className="w-4 h-4 text-primary" />
                    <span
                      className="font-mono text-sm"
                      title={getContractAddress(contract)}
                    >
                      {truncateAddress(getContractAddress(contract))}
                    </span>
                    <button
                      onClick={() => copyToClipboard(getContractAddress(contract), contract.id)}
                      className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
                      title="Copy address"
                    >
                      {copiedId === contract.id ? (
                        <Check className="w-3.5 h-3.5 text-success" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </TableCell>
                <TableCell>
                  <span className="text-sm">{contract.name || '-'}</span>
                </TableCell>
                <TableCell className="text-center">
                  {contract.abi ? (
                    <span title="ABI loaded">
                      <Check className="w-4 h-4 text-success mx-auto" />
                    </span>
                  ) : (
                    <span className="text-neutral-400" title="No ABI">-</span>
                  )}
                </TableCell>
                <TableCell className="text-center">
                  {(() => {
                    const summary = grantSummary[contract.id];
                    const groupCount = summary?.count ?? 0;
                    const groupNames = summary?.groups?.map(g => g.name).join(', ') ?? '';
                    return (
                      <span
                        className={`inline-flex items-center justify-center rounded-full px-2 py-0.5 text-xs font-medium cursor-default ${
                          groupCount > 0
                            ? 'bg-primary-50 text-primary-700'
                            : 'bg-neutral-100 text-neutral-400'
                        }`}
                        title={groupCount > 0 ? groupNames : 'No groups assigned'}
                      >
                        {groupCount}
                      </span>
                    );
                  })()}
                </TableCell>
                <TableCell>
                  <div className="flex flex-col gap-0.5">
                    <span className="text-sm text-neutral-500">
                      {formatDate(contract.created_at)}
                    </span>
                    {contract.metadata?.deploy_block && (() => {
                      const raw = contract.metadata.deploy_block as string;
                      const blockNum = raw.startsWith('0x') ? parseInt(raw, 16) : Number(raw);
                      return (
                        <span className="text-xs text-neutral-400 font-mono">
                          block {isNaN(blockNum) ? raw : blockNum.toLocaleString()}
                        </span>
                      );
                    })()}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setManagingGrants(contract)}
                      title="Manage permissions"
                      className="text-primary hover:text-primary-600 hover:bg-primary-50"
                    >
                      <Shield className="w-4 h-4" />
                    </Button>
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
                      onClick={() => setDeleteTarget(contract)}
                      className="text-error-dark hover:text-error-dark hover:bg-error-light"
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

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onPageChange={(newOffset) => loadContracts(newOffset)} />

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

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Contract"
        description={`Are you sure you want to delete "${deleteTarget ? (deleteTarget.name || getContractAddress(deleteTarget)) : ''}"? This cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={handleDeleteConfirm}
        variant="destructive"
      />

      {/* Delete Error Alert */}
      <AlertDialog
        open={showDeleteError}
        onOpenChange={setShowDeleteError}
        title="Delete Failed"
        description="Failed to delete contract."
        buttonLabel="OK"
        variant="error"
      />

      {/* Sync Error Alert */}
      <AlertDialog
        open={!!syncError}
        onOpenChange={() => setSyncError(null)}
        title="Sync Error"
        description={syncError || ''}
        buttonLabel="OK"
        variant="error"
      />

      {/* Grants Manager Dialog */}
      <Dialog open={!!managingGrants} onOpenChange={open => !open && setManagingGrants(null)}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Contract Permissions</DialogTitle>
          </DialogHeader>
          {managingGrants && (
            <ContractGrantsManager
              key={managingGrants.id}
              orgId={orgId}
              contract={managingGrants}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Sync Results Dialog */}
      <Dialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Sync with Chain Results</DialogTitle>
          </DialogHeader>
          {syncResult && (
            <div className="space-y-4">
              {/* Summary */}
              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="p-3 rounded-lg bg-success-light">
                  <div className="text-2xl font-semibold text-success-dark">
                    {syncResult.existing?.length ?? 0}
                  </div>
                  <div className="text-xs text-success-dark">On Chain</div>
                </div>
                <div className="p-3 rounded-lg bg-amber-100">
                  <div className="text-2xl font-semibold text-amber-800">
                    {syncResult.missing?.length ?? 0}
                  </div>
                  <div className="text-xs text-amber-800">Missing</div>
                </div>
                <div className="p-3 rounded-lg bg-error-light">
                  <div className="text-2xl font-semibold text-error-dark">
                    {syncResult.errors?.length ?? 0}
                  </div>
                  <div className="text-xs text-error-dark">Errors</div>
                </div>
              </div>

              {/* All synced message */}
              {!syncResult.missing?.length && !syncResult.errors?.length && (
                <div className="p-4 rounded-lg bg-success-light text-success-dark text-center">
                  <Check className="w-6 h-6 mx-auto mb-2" />
                  <p className="font-medium">All contracts exist on chain!</p>
                </div>
              )}

              {/* Missing contracts list */}
              {(syncResult.missing?.length ?? 0) > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-amber-800">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="font-medium text-sm">
                      Contracts not found on chain:
                    </span>
                  </div>
                  <div className="max-h-40 overflow-y-auto border rounded-lg divide-y">
                    {(syncResult.missing ?? []).map((contract: ContractSyncStatus) => (
                      <div
                        key={contract.id}
                        className="px-3 py-2 flex items-center justify-between text-sm"
                      >
                        <span className="font-mono text-xs">
                          {truncateAddress(contract.address)}
                        </span>
                        <span className="text-neutral-500">
                          {contract.name || 'Unnamed'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Errors list */}
              {(syncResult.errors?.length ?? 0) > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-error-dark">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="font-medium text-sm">
                      Chain unavailable for these contracts (not deleted):
                    </span>
                  </div>
                  <div className="max-h-40 overflow-y-auto border rounded-lg divide-y">
                    {(syncResult.errors ?? []).map((contract: ContractSyncStatus) => (
                      <div
                        key={contract.id}
                        className="px-3 py-2 text-sm"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs">
                            {truncateAddress(contract.address)}
                          </span>
                          <span className="text-neutral-500">
                            {contract.name || 'Unnamed'}
                          </span>
                        </div>
                        {contract.error && (
                          <div className="text-xs text-error-dark mt-1">
                            {contract.error}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="flex justify-end gap-2 pt-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowSyncDialog(false);
                    setSyncResult(null);
                  }}
                >
                  Close
                </Button>
                {(syncResult.missing?.length ?? 0) > 0 && (
                  <Button
                    variant="destructive"
                    onClick={handleDeleteStale}
                    disabled={deletingStale}
                    className="gap-2"
                  >
                    {deletingStale ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Deleting...
                      </>
                    ) : (
                      <>
                        <Trash2 className="w-4 h-4" />
                        Delete {syncResult.missing?.length ?? 0} Missing Contract
                        {(syncResult.missing?.length ?? 0) > 1 ? 's' : ''}
                      </>
                    )}
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
