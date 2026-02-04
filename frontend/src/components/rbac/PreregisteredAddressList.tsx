import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { PreregisteredAddress } from '@/types/rbac';
import PreregisterForm from './PreregisterForm';
import { useOrgContext } from './RBACManager';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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
import { Hash, Plus, Trash2, Loader2, Check, Clock, Copy, Factory, FileCode, Pencil } from 'lucide-react';
import { Textarea } from '@/components/ui/textarea';

export default function PreregisteredAddressList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [addresses, setAddresses] = useState<PreregisteredAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<PreregisteredAddress | null>(null);
  const [showDeleteError, setShowDeleteError] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [factoryAddress, setFactoryAddress] = useState<string | null>(null);
  const [factoryCopied, setFactoryCopied] = useState(false);
  // ABI editor state
  const [abiTarget, setAbiTarget] = useState<PreregisteredAddress | null>(null);
  const [abiValue, setAbiValue] = useState('');
  const [abiSaving, setAbiSaving] = useState(false);
  const [abiError, setAbiError] = useState<string | null>(null);

  useEffect(() => {
    if (orgId) {
      loadAddresses();
    }
  }, [orgId]);

  // Load factory address from org config only (per-org isolation)
  useEffect(() => {
    if (!orgId) return;

    const loadFactory = async () => {
      try {
        const response = await rbacApi.orgConfig.getCreate3Factory(orgId);
        if (response.data?.factory && response.data?.configured) {
          setFactoryAddress(response.data.factory);
        } else {
          setFactoryAddress(null);
        }
      } catch {
        setFactoryAddress(null);
      }
    };
    loadFactory();
  }, [orgId]);

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const copyFactory = async () => {
    if (!factoryAddress) return;
    try {
      await navigator.clipboard.writeText(factoryAddress);
      setFactoryCopied(true);
      setTimeout(() => setFactoryCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const loadAddresses = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      const response = await rbacApi.preregisteredAddresses.list(orgId);
      setAddresses(response.data || []);
    } catch (error) {
      console.error('Failed to load preregistered addresses:', error);
      setAddresses([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;

    try {
      await rbacApi.preregisteredAddresses.delete(orgId, deleteTarget.address);
      setDeleteTarget(null);
      await loadAddresses();
    } catch (error) {
      console.error('Failed to delete preregistered address:', error);
      setDeleteTarget(null);
      setShowDeleteError(true);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    await loadAddresses();
  };

  const openAbiEditor = (addr: PreregisteredAddress) => {
    setAbiTarget(addr);
    setAbiValue(addr.constructor_abi || '');
    setAbiError(null);
  };

  const handleAbiSave = async () => {
    if (!abiTarget) return;

    // Validate JSON if not empty
    if (abiValue.trim()) {
      try {
        JSON.parse(abiValue);
      } catch {
        setAbiError('Invalid JSON format');
        return;
      }
    }

    setAbiSaving(true);
    setAbiError(null);

    try {
      await rbacApi.preregisteredAddresses.updateABI(orgId, abiTarget.address, abiValue.trim());
      setAbiTarget(null);
      await loadAddresses();
    } catch (error) {
      console.error('Failed to update ABI:', error);
      setAbiError('Failed to save ABI. Please try again.');
    } finally {
      setAbiSaving(false);
    }
  };

  const truncateAddress = (address: string | undefined) => {
    if (!address) return '-';
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  const truncateSalt = (salt: string | undefined) => {
    if (!salt) return '-';
    if (salt.length <= 20) return salt;
    return `${salt.slice(0, 10)}...${salt.slice(-6)}`;
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
          <h3 className="text-sm font-medium text-[#374151]">Pre-registered Addresses</h3>
          <p className="text-xs text-[#6B7280] mt-0.5">
            CREATE3 addresses whitelisted for future deployments
          </p>
        </div>
        <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
          <Plus className="w-4 h-4" />
          Pre-register Addresses
        </Button>
      </div>

      {/* Factory Address Display */}
      {factoryAddress && (
        <div className="p-3 rounded-lg bg-[#F0F9FF] border border-[#BAE6FD] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-[#0EA5E9] flex items-center justify-center">
              <Factory className="w-4 h-4 text-white" />
            </div>
            <div>
              <p className="text-xs font-medium text-[#0369A1]">CREATE3 Factory</p>
              <p className="font-mono text-sm text-[#0C4A6E]" title={factoryAddress}>
                {factoryAddress}
              </p>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={copyFactory}
            className="h-8 w-8 p-0 text-[#0369A1] hover:text-[#0C4A6E] hover:bg-[#E0F2FE]"
            title="Copy factory address"
          >
            {factoryCopied ? (
              <Check className="w-4 h-4 text-[#22C55E]" />
            ) : (
              <Copy className="w-4 h-4" />
            )}
          </Button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-[#94A3B8] animate-spin" />
        </div>
      ) : addresses.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
            <Hash className="w-8 h-8 text-[#94A3B8]" />
          </div>
          <p className="text-[#6B7280] mb-2">No pre-registered addresses</p>
          <p className="text-[#94A3B8] text-sm mb-4">
            Pre-register CREATE3 addresses to whitelist future deployment targets
          </p>
          <Button
            variant="outline"
            onClick={() => setShowForm(true)}
            className="gap-2"
          >
            <Plus className="w-4 h-4" />
            Pre-register your first addresses
          </Button>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Address</TableHead>
              <TableHead>Factory</TableHead>
              <TableHead>Salt</TableHead>
              <TableHead>Note</TableHead>
              <TableHead>ABI</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {addresses.map((addr, index) => (
              <TableRow
                key={addr.id}
                className="animate-fade-in"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Hash className="w-4 h-4 text-[#8950FA]" />
                    <span
                      className="font-mono text-sm"
                      title={addr.address}
                    >
                      {truncateAddress(addr.address)}
                    </span>
                    <button
                      onClick={() => copyToClipboard(addr.address, `addr-${addr.id}`)}
                      className="p-1 rounded hover:bg-[#F1F5F9] text-[#94A3B8] hover:text-[#6B7280] transition-colors"
                      title="Copy address"
                    >
                      {copiedId === `addr-${addr.id}` ? (
                        <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <span
                      className="font-mono text-sm text-[#6B7280]"
                      title={addr.factory}
                    >
                      {truncateAddress(addr.factory)}
                    </span>
                    <button
                      onClick={() => copyToClipboard(addr.factory, `factory-${addr.id}`)}
                      className="p-1 rounded hover:bg-[#F1F5F9] text-[#94A3B8] hover:text-[#6B7280] transition-colors"
                      title="Copy factory address"
                    >
                      {copiedId === `factory-${addr.id}` ? (
                        <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <span
                      className="font-mono text-xs text-[#94A3B8]"
                      title={addr.salt}
                    >
                      {truncateSalt(addr.salt)}
                    </span>
                    <button
                      onClick={() => copyToClipboard(addr.salt, `salt-${addr.id}`)}
                      className="p-1 rounded hover:bg-[#F1F5F9] text-[#94A3B8] hover:text-[#6B7280] transition-colors"
                      title="Copy salt"
                    >
                      {copiedId === `salt-${addr.id}` ? (
                        <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </TableCell>
                <TableCell>
                  <span className="text-sm text-[#6B7280]">
                    {addr.note || '-'}
                  </span>
                </TableCell>
                <TableCell>
                  {addr.constructor_abi ? (
                    <Badge variant="default" className="gap-1 bg-[#8950FA] hover:bg-[#7C3AED]">
                      <FileCode className="w-3 h-3" />
                      Set
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="gap-1 text-[#94A3B8]">
                      <FileCode className="w-3 h-3" />
                      Not set
                    </Badge>
                  )}
                </TableCell>
                <TableCell>
                  {addr.used_at ? (
                    <Badge variant="default" className="gap-1 bg-[#10B981] hover:bg-[#059669]">
                      <Check className="w-3 h-3" />
                      Used
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="gap-1 text-[#6B7280]">
                      <Clock className="w-3 h-3" />
                      Pending
                    </Badge>
                  )}
                </TableCell>
                <TableCell>
                  <span className="text-sm text-[#6B7280]">
                    {formatDate(addr.created_at)}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => openAbiEditor(addr)}
                      className="text-[#6B7280] hover:text-[#374151] hover:bg-[#F1F5F9]"
                      title="Edit contract ABI"
                    >
                      <Pencil className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteTarget(addr)}
                      className="text-[#991B1B] hover:text-[#7F1D1D] hover:bg-[#FEE2E2]"
                      title="Delete pre-registered address"
                      disabled={!!addr.used_at}
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

      {/* Pre-register Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Pre-register CREATE3 Addresses</DialogTitle>
          </DialogHeader>
          <PreregisterForm
            orgId={orgId}
            onClose={() => setShowForm(false)}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Pre-registered Address"
        description={`Are you sure you want to delete the pre-registered address "${deleteTarget?.address || ''}"? This cannot be undone.`}
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
        description="Failed to delete pre-registered address."
        buttonLabel="OK"
        variant="error"
      />

      {/* ABI Editor Dialog */}
      <Dialog open={!!abiTarget} onOpenChange={(open) => !open && setAbiTarget(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-[#8950FA]" />
              Edit Constructor ABI
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0]">
              <p className="text-xs font-medium text-[#64748B] mb-1">Address</p>
              <p className="font-mono text-sm text-[#334155]">{abiTarget?.address}</p>
            </div>

            <div className="space-y-2">
              <label htmlFor="constructor-abi" className="text-sm font-medium text-[#374151]">
                Contract ABI (JSON)
              </label>
              <p className="text-xs text-[#6B7280]">
                Paste the contract ABI JSON. This is used to validate constructor arguments
                containing addresses (e.g., immutable address variables).
              </p>
              <Textarea
                id="constructor-abi"
                value={abiValue}
                onChange={(e) => {
                  setAbiValue(e.target.value);
                  setAbiError(null);
                }}
                placeholder='[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]'
                className="font-mono text-sm min-h-[200px] resize-y"
              />
              {abiError && (
                <p className="text-sm text-[#DC2626]">{abiError}</p>
              )}
            </div>

            <div className="p-3 rounded-lg bg-[#FFFBEB] border border-[#FDE68A]">
              <p className="text-xs text-[#92400E]">
                <strong>Note:</strong> The ABI is required when deploying contracts with constructor
                arguments that contain addresses. If the ABI is not set, deployments with constructor
                args will be rejected.
              </p>
            </div>
          </div>

          <div className="flex justify-end gap-3">
            <Button
              variant="outline"
              onClick={() => setAbiTarget(null)}
              disabled={abiSaving}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAbiSave}
              disabled={abiSaving}
              className="gap-2"
            >
              {abiSaving && <Loader2 className="w-4 h-4 animate-spin" />}
              Save ABI
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
