import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { GroupWithAccess } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader2, ArrowRight } from 'lucide-react';

interface MoveToGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  orgId: string;
  selectedContractIds: string[];
  onSuccess: () => void;
}

type TargetMode = 'existing' | 'new';

function toSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-]/g, '');
}

export default function MoveToGroupDialog({
  open,
  onOpenChange,
  orgId,
  selectedContractIds,
  onSuccess,
}: MoveToGroupDialogProps) {
  const [mode, setMode] = useState<TargetMode>('existing');
  const [groups, setGroups] = useState<GroupWithAccess[]>([]);
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [newName, setNewName] = useState('');
  const [newSlug, setNewSlug] = useState('');
  const [slugManuallyEdited, setSlugManuallyEdited] = useState(false);
  const [deleteEmptyAutoGroups, setDeleteEmptyAutoGroups] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load non-auto-created groups when dialog opens
  useEffect(() => {
    if (!open) return;

    setError(null);
    setLoadingGroups(true);

    rbacApi.groups
      .list(orgId, { limit: 200 })
      .then((res) => {
        const allGroups = res.data.data || [];
        const manual = allGroups.filter((g: GroupWithAccess) => !g.group.auto_created);
        setGroups(manual);
      })
      .catch((err) => {
        console.error('Failed to load groups:', err);
        setError('Failed to load groups');
      })
      .finally(() => setLoadingGroups(false));
  }, [open, orgId]);

  // Reset form state when dialog opens
  useEffect(() => {
    if (open) {
      setMode('existing');
      setSelectedGroupId('');
      setNewName('');
      setNewSlug('');
      setSlugManuallyEdited(false);
      setDeleteEmptyAutoGroups(true);
      setSubmitting(false);
      setError(null);
    }
  }, [open]);

  // Auto-generate slug from name
  useEffect(() => {
    if (!slugManuallyEdited) {
      setNewSlug(toSlug(newName));
    }
  }, [newName, slugManuallyEdited]);

  const canSubmit =
    !submitting &&
    selectedContractIds.length > 0 &&
    ((mode === 'existing' && selectedGroupId !== '') ||
      (mode === 'new' && newName.trim() !== '' && newSlug.trim() !== ''));

  async function handleSubmit() {
    setError(null);
    setSubmitting(true);

    try {
      await rbacApi.contracts.batchMove(orgId, {
        contract_ids: selectedContractIds,
        ...(mode === 'existing'
          ? { target_group_id: selectedGroupId }
          : { new_group: { name: newName.trim(), slug: newSlug.trim() } }),
        delete_empty_auto_groups: deleteEmptyAutoGroups,
      });
      onSuccess();
      onOpenChange(false);
    } catch (err: unknown) {
      // Extract error message from Axios response if available
      const axiosErr = err as { response?: { data?: { error?: string } } };
      const message =
        axiosErr?.response?.data?.error ||
        (err instanceof Error ? err.message : 'Failed to move contracts');
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="move-dialog" className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowRight className="h-5 w-5" />
            Move Contracts to Group
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <p className="text-sm text-neutral-500">
            Moving {selectedContractIds.length} contract
            {selectedContractIds.length !== 1 ? 's' : ''} to a group.
          </p>

          {error && (
            <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          {/* Target mode selection */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Destination</label>
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  data-testid="move-existing-radio"
                  type="radio"
                  name="targetMode"
                  checked={mode === 'existing'}
                  onChange={() => setMode('existing')}
                  className="accent-primary"
                />
                Existing group
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  data-testid="move-new-radio"
                  type="radio"
                  name="targetMode"
                  checked={mode === 'new'}
                  onChange={() => setMode('new')}
                  className="accent-primary"
                />
                Create new group
              </label>
            </div>
          </div>

          {/* Existing group selector */}
          {mode === 'existing' && (
            <div className="space-y-1">
              <label className="text-sm font-medium">Target group</label>
              {loadingGroups ? (
                <div className="flex items-center gap-2 text-sm text-neutral-500 py-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading groups...
                </div>
              ) : groups.length === 0 ? (
                <p className="text-xs text-neutral-500">
                  No manually created groups found. Create a new group instead.
                </p>
              ) : (
                <Select value={selectedGroupId} onValueChange={setSelectedGroupId}>
                  <SelectTrigger data-testid="move-group-select">
                    <SelectValue placeholder="Select a group" />
                  </SelectTrigger>
                  <SelectContent>
                    {groups.map((g) => (
                      <SelectItem key={g.group.id} value={g.group.id}>
                        {g.group.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          )}

          {/* New group form */}
          {mode === 'new' && (
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-sm font-medium">Group name</label>
                <Input
                  data-testid="move-new-name"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. DeFi Contracts"
                />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium">Slug</label>
                <Input
                  data-testid="move-new-slug"
                  value={newSlug}
                  onChange={(e) => {
                    setNewSlug(e.target.value);
                    setSlugManuallyEdited(true);
                  }}
                  placeholder="e.g. defi-contracts"
                />
                <p className="text-xs text-neutral-500">
                  Auto-generated from name. Edit to customize.
                </p>
              </div>
            </div>
          )}

          {/* Cleanup option */}
          <div className="flex items-center gap-2">
            <Checkbox
              data-testid="move-delete-empty-checkbox"
              id="deleteEmpty"
              checked={deleteEmptyAutoGroups}
              onCheckedChange={(checked) =>
                setDeleteEmptyAutoGroups(checked === true)
              }
            />
            <label htmlFor="deleteEmpty" className="text-sm cursor-pointer">
              Delete empty auto-created groups after move
            </label>
          </div>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button data-testid="move-cancel-btn" variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button data-testid="move-confirm-btn" onClick={handleSubmit} disabled={!canSubmit}>
            {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Move {selectedContractIds.length} Contract
            {selectedContractIds.length !== 1 ? 's' : ''}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
