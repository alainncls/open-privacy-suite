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
import { Hash, Plus, Trash2, Loader2, Check, Clock } from 'lucide-react';

export default function PreregisteredAddressList() {
  const { selectedOrg } = useOrgContext();
  const orgId = selectedOrg?.id || '';
  const [addresses, setAddresses] = useState<PreregisteredAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<PreregisteredAddress | null>(null);
  const [showDeleteError, setShowDeleteError] = useState(false);

  useEffect(() => {
    if (orgId) {
      loadAddresses();
    }
  }, [orgId]);

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
                  </div>
                </TableCell>
                <TableCell>
                  <span
                    className="font-mono text-sm text-[#6B7280]"
                    title={addr.factory}
                  >
                    {truncateAddress(addr.factory)}
                  </span>
                </TableCell>
                <TableCell>
                  <span
                    className="font-mono text-xs text-[#94A3B8]"
                    title={addr.salt}
                  >
                    {truncateSalt(addr.salt)}
                  </span>
                </TableCell>
                <TableCell>
                  <span className="text-sm text-[#6B7280]">
                    {addr.note || '-'}
                  </span>
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
    </div>
  );
}
