import { useEffect, useMemo, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { User, MembershipWithDetails, EffectivePermissions } from '@/types/rbac';
import { useOrgContext } from './RBACManager';
import { CLAIM_LABELS } from '@/types/rbac';
import MembershipForm from './MembershipForm';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { AddressDisplay } from '@/components/ui/AddressDisplay';
import { useEnsNames } from '@/hooks/useEnsNames';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import {
  Check,
  X,
  Loader2,
  Plus,
  Trash2,
  FolderTree,
  Save,
  AlertCircle,
  Wallet,
} from 'lucide-react';

interface UserDetailProps {
  user: User;
  onUpdate: () => void;
}

interface LinkedAddress {
  address: string;
  verified_at: string;
  ens_name?: string;
  ens_resolved_at?: string;
}

export default function UserDetail({ user, onUpdate }: UserDetailProps) {
  const { organizations, selectedOrg } = useOrgContext();
  const [memberships, setMemberships] = useState<MembershipWithDetails[]>([]);
  const [effectivePermsByOrg, setEffectivePermsByOrg] = useState<Record<string, EffectivePermissions>>({});
  const [loadingPerms, setLoadingPerms] = useState(false);
  const [linkedAddresses, setLinkedAddresses] = useState<LinkedAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingAddresses, setLoadingAddresses] = useState(true);
  const [showMembershipForm, setShowMembershipForm] = useState(false);
  const [deleteMembershipTarget, setDeleteMembershipTarget] = useState<string | null>(null);
  const [showMembershipDeleteError, setShowMembershipDeleteError] = useState(false);

  // Group memberships by organization
  const membershipsByOrg = useMemo(() => {
    const grouped: Record<string, MembershipWithDetails[]> = {};
    for (const m of memberships) {
      const orgId = m.group?.org_id || 'unknown';
      if (!grouped[orgId]) {
        grouped[orgId] = [];
      }
      grouped[orgId].push(m);
    }
    return grouped;
  }, [memberships]);

  // Get unique org IDs from memberships
  const userOrgIds = useMemo(() => {
    return Object.keys(membershipsByOrg).filter(id => id !== 'unknown');
  }, [membershipsByOrg]);

  // Map org ID to org object for display
  const orgById = useMemo(() => {
    const map: Record<string, { name: string; slug: string }> = {};
    for (const org of organizations) {
      map[org.id] = { name: org.name, slug: org.slug };
    }
    return map;
  }, [organizations]);

  // Build cache of ENS names from API response
  const cachedEnsNames = useMemo(() => {
    const cache: Record<string, string | null> = {};
    for (const addr of linkedAddresses) {
      if (addr.ens_name !== undefined) {
        cache[addr.address.toLowerCase()] = addr.ens_name || null;
      }
    }
    return cache;
  }, [linkedAddresses]);

  // ENS name resolution for linked addresses (uses cache from API)
  const { data: ensNames, isLoading: loadingEns } = useEnsNames(
    linkedAddresses.map(a => a.address),
    { cachedNames: cachedEnsNames }
  );

  // Edit form state
  const [kyc, setKyc] = useState(user.kyc);
  const [banned, setBanned] = useState(user.banned);
  const [note, setNote] = useState(user.note || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);

  useEffect(() => {
    loadMemberships();
    loadLinkedAddresses();
  }, [user.id]);

  // Load effective permissions for all orgs user is a member of
  useEffect(() => {
    if (userOrgIds.length > 0) {
      loadAllEffectivePermissions();
    }
  }, [userOrgIds.join(',')]);

  useEffect(() => {
    setHasChanges(kyc !== user.kyc || banned !== user.banned || note !== (user.note || ''));
  }, [kyc, banned, note, user]);

  const loadMemberships = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.users.getMemberships(user.id);
      setMemberships(response.data || []);
    } catch (error) {
      console.error('Failed to load memberships:', error);
      setMemberships([]);
    } finally {
      setLoading(false);
    }
  };

  const loadLinkedAddresses = async () => {
    try {
      setLoadingAddresses(true);
      const response = await rbacApi.users.getLinkedAddresses(user.id);
      setLinkedAddresses(response.data.addresses || []);
    } catch (error) {
      console.error('Failed to load linked addresses:', error);
      setLinkedAddresses([]);
    } finally {
      setLoadingAddresses(false);
    }
  };

  const loadAllEffectivePermissions = async () => {
    if (userOrgIds.length === 0) return;

    setLoadingPerms(true);
    const permsMap: Record<string, EffectivePermissions> = {};

    try {
      // Load permissions for each org in parallel
      const results = await Promise.allSettled(
        userOrgIds.map(async (orgId) => {
          const org = orgById[orgId];
          if (!org) return null;
          const response = await rbacApi.users.getEffectivePermissions(user.id, org.slug);
          return { orgId, perms: response.data };
        })
      );

      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          permsMap[result.value.orgId] = result.value.perms;
        }
      }

      setEffectivePermsByOrg(permsMap);
    } catch (err) {
      console.error('Failed to load effective permissions:', err);
    } finally {
      setLoadingPerms(false);
    }
  };

  const handleDeleteMembershipConfirm = async () => {
    if (!deleteMembershipTarget) return;
    try {
      await rbacApi.users.deleteMembership(user.id, deleteMembershipTarget);
      setDeleteMembershipTarget(null);
      await loadMemberships();
      // Permissions will reload via useEffect when userOrgIds changes
      onUpdate();
    } catch (error) {
      console.error('Failed to delete membership:', error);
      setDeleteMembershipTarget(null);
      setShowMembershipDeleteError(true);
    }
  };

  const handleSaveUser = async () => {
    setSaving(true);
    setError(null);
    try {
      await rbacApi.users.update(user.id, { kyc, banned, note });
      onUpdate();
      setHasChanges(false);
    } catch (err: unknown) {
      console.error('Failed to update user:', err);
      const axiosError = err as {
        response?: { data?: { error?: string } };
      };
      setError(axiosError.response?.data?.error || 'Failed to update user.');
    } finally {
      setSaving(false);
    }
  };

  const handleMembershipSave = async () => {
    setShowMembershipForm(false);
    await loadMemberships();
    // Permissions will reload via useEffect when userOrgIds changes
    onUpdate();
  };

  const getClaimColor = (claim: string) => {
    switch (claim) {
      case 'admin':
        return 'bg-red-100 text-[#991B1B] border-red-300';
      case 'deployer':
        return 'bg-purple-100 text-purple-700 border-purple-300';
      case 'upgrade':
        return 'bg-orange-100 text-orange-700 border-orange-300';
      case 'writer':
        return 'bg-blue-100 text-blue-700 border-blue-300';
      case 'reader':
        return 'bg-green-100 text-green-700 border-green-300';
      default:
        return 'bg-gray-100 text-gray-600 border-gray-300';
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      {/* User Info */}
      <div className="p-4 rounded-lg bg-[#F1F5F9] space-y-4">
        <h4 className="text-sm font-medium text-[#374151]">User Information</h4>

        <div className="space-y-2">
          <label className="block text-xs text-[#6B7280]">External ID (DID)</label>
          <Input
            value={user.external_id}
            disabled
            className="font-mono text-sm bg-[#F1F5F9]"
          />
        </div>

        <div className="flex gap-6">
          <label className="flex items-center gap-3 cursor-pointer group">
            <div className="relative">
              <input
                type="checkbox"
                checked={kyc}
                onChange={e => setKyc(e.target.checked)}
                className="peer sr-only"
              />
              <div className="w-5 h-5 rounded border border-[#CBD5E1] bg-[#F1F5F9] peer-checked:bg-green-500 peer-checked:border-green-500 transition-all flex items-center justify-center">
                {kyc && (
                  <Check className="w-3 h-3 text-white" />
                )}
              </div>
            </div>
            <span className="text-sm text-[#374151] group-hover:text-[#0F0F0F] transition-colors">
              KYC Verified
            </span>
          </label>

          <label className="flex items-center gap-3 cursor-pointer group">
            <div className="relative">
              <input
                type="checkbox"
                checked={banned}
                onChange={e => setBanned(e.target.checked)}
                className="peer sr-only"
              />
              <div className="w-5 h-5 rounded border border-[#CBD5E1] bg-[#F1F5F9] peer-checked:bg-red-500 peer-checked:border-red-500 transition-all flex items-center justify-center">
                {banned && (
                  <X className="w-3 h-3 text-white" />
                )}
              </div>
            </div>
            <span className="text-sm text-[#374151] group-hover:text-[#0F0F0F] transition-colors">
              Banned
            </span>
          </label>
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-[#6B7280]">Note</label>
          <Textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Add a note about this user..."
            className="h-20"
          />
        </div>

        {hasChanges && (
          <div className="flex justify-end">
            <Button onClick={handleSaveUser} disabled={saving} size="sm" className="gap-2">
              {saving ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  Save Changes
                </>
              )}
            </Button>
          </div>
        )}
      </div>

      {/* Linked Addresses */}
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-[#374151] flex items-center gap-2">
          <Wallet className="w-4 h-4" />
          Linked Wallet Addresses
        </h4>

        {loadingAddresses ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-5 h-5 text-[#94A3B8] animate-spin" />
          </div>
        ) : linkedAddresses.length === 0 ? (
          <div className="text-center py-6 text-[#94A3B8] text-sm">
            No linked wallet addresses
          </div>
        ) : (
          <div className="space-y-2">
            {linkedAddresses.map((addr) => (
              <div
                key={addr.address}
                className="flex items-center justify-between p-3 rounded-lg bg-[#F1F5F9]"
              >
                <AddressDisplay
                  address={addr.address}
                  ensName={ensNames?.[addr.address.toLowerCase()]}
                />
                <div className="flex items-center gap-2">
                  {loadingEns && !ensNames?.[addr.address.toLowerCase()] && (
                    <Loader2 className="w-3 h-3 text-[#94A3B8] animate-spin" />
                  )}
                  <span className="text-xs text-[#94A3B8]">
                    Verified {new Date(addr.verified_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Memberships */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium text-[#374151]">Group Memberships</h4>
          <Button
            onClick={() => setShowMembershipForm(true)}
            size="sm"
            variant="outline"
            className="gap-1"
          >
            <Plus className="w-4 h-4" />
            Add
          </Button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-5 h-5 text-[#94A3B8] animate-spin" />
          </div>
        ) : memberships.length === 0 ? (
          <div className="text-center py-6 text-[#94A3B8] text-sm">
            No group memberships
          </div>
        ) : (
          <div className="space-y-4">
            {Object.entries(membershipsByOrg).map(([orgId, orgMemberships]) => (
              <div key={orgId} className="space-y-2">
                {/* Organization header */}
                <div className="text-xs font-medium text-[#6B7280] uppercase tracking-wide px-1">
                  {orgById[orgId]?.name || 'Unknown Organization'}
                </div>
                {/* Memberships in this org */}
                {orgMemberships.map((m, idx) => (
                  <div
                    key={m.membership?.id || idx}
                    className="flex items-center justify-between p-3 rounded-lg bg-[#F1F5F9]"
                  >
                    <div className="flex items-center gap-3">
                      <FolderTree className="w-4 h-4 text-[#8950FA]" />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm">{m.group?.name || 'Unknown Group'}</span>
                          {/* Only show path if it differs from name (indicates hierarchy) */}
                          {m.group?.path && m.group.path !== m.group.name && m.group.path !== m.group.slug && (
                            <Badge variant="outline" className="text-xs font-mono">
                              {m.group.path}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          {m.membership?.source && (
                            <Badge
                              variant="outline"
                              className={`text-xs ${
                                m.membership.source === 'zk_attested'
                                  ? 'text-purple-700 border-purple-300 bg-purple-50'
                                  : 'text-[#6B7280]'
                              }`}
                            >
                              {m.membership.source === 'admin'
                                ? 'Added by admin'
                                : m.membership.source === 'zk_attested'
                                ? 'ZK Attested'
                                : m.membership.source}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    {m.membership?.id && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeleteMembershipTarget(m.membership.id)}
                        className="text-[#991B1B] hover:text-red-300 hover:bg-red-500/10"
                        aria-label="Remove membership"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Effective Permissions */}
      {userOrgIds.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-[#374151]">Effective Permissions</h4>

          {loadingPerms ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="w-5 h-5 text-[#94A3B8] animate-spin" />
            </div>
          ) : (
            <div className="space-y-4">
              {userOrgIds.map((orgId) => {
                const effectivePerms = effectivePermsByOrg[orgId];
                const org = orgById[orgId];

                return (
                  <div key={orgId} className="space-y-2">
                    {/* Organization header */}
                    <div className="text-xs font-medium text-[#6B7280] uppercase tracking-wide px-1">
                      {org?.name || 'Unknown Organization'}
                    </div>

                    {effectivePerms ? (
                      <div className="p-4 rounded-lg bg-[#F1F5F9] space-y-4">
                        <div>
                          <label className="text-xs text-[#6B7280] mb-1 block">
                            Access Level
                            <span className="ml-1 text-[#94A3B8]" title="Permissions for contracts not explicitly configured">
                              (for unregistered contracts)
                            </span>
                          </label>
                          {effectivePerms.default_claims && effectivePerms.default_claims.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {effectivePerms.default_claims.map(claim => (
                                <Badge
                                  key={claim}
                                  variant="outline"
                                  className={`text-xs ${getClaimColor(claim)}`}
                                >
                                  {CLAIM_LABELS[claim] || claim}
                                </Badge>
                              ))}
                            </div>
                          ) : (
                            <span className="text-[#94A3B8] text-sm">None</span>
                          )}
                        </div>

                        <div>
                          <label className="text-xs text-[#6B7280] mb-1 block">
                            Allowed Methods {effectivePerms.allowed_methods && effectivePerms.allowed_methods.length > 0
                              ? `(${effectivePerms.allowed_methods.length})`
                              : ''}
                          </label>
                          {effectivePerms.allowed_methods && effectivePerms.allowed_methods.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {effectivePerms.allowed_methods.slice(0, 10).map((method: string) => (
                                <Badge key={method} variant="outline" className="text-xs font-mono">
                                  {method}
                                </Badge>
                              ))}
                              {effectivePerms.allowed_methods.length > 10 && (
                                <Badge variant="secondary" className="text-xs">
                                  +{effectivePerms.allowed_methods.length - 10} more
                                </Badge>
                              )}
                            </div>
                          ) : (
                            <span className="text-green-600 text-sm">All methods (unrestricted)</span>
                          )}
                        </div>

                        <div className="flex gap-4">
                          <div>
                            <label className="text-xs text-[#6B7280] mb-1 block">Rate Limit (RPS)</label>
                            <span className="text-sm">
                              {effectivePerms.rate_limit_rps ?? 'Unlimited'}
                            </span>
                          </div>
                          <div>
                            <label className="text-xs text-[#6B7280] mb-1 block">Rate Limit (Daily)</label>
                            <span className="text-sm">
                              {effectivePerms.rate_limit_daily ?? 'Unlimited'}
                            </span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="p-4 rounded-lg bg-[#F1F5F9] text-[#94A3B8] text-sm">
                        No permissions configured
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Add Membership Dialog */}
      <Dialog open={showMembershipForm} onOpenChange={setShowMembershipForm}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add Group Membership</DialogTitle>
          </DialogHeader>
          <MembershipForm
            userId={user.id}
            organizations={organizations}
            existingMemberships={memberships}
            onClose={() => setShowMembershipForm(false)}
            onSave={handleMembershipSave}
          />
        </DialogContent>
      </Dialog>

      {/* Delete Membership Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteMembershipTarget}
        onOpenChange={open => !open && setDeleteMembershipTarget(null)}
        title="Remove Membership"
        description="Are you sure you want to remove this group membership?"
        confirmLabel="Remove"
        cancelLabel="Cancel"
        onConfirm={handleDeleteMembershipConfirm}
        variant="destructive"
      />

      {/* Delete Membership Error Alert */}
      <AlertDialog
        open={showMembershipDeleteError}
        onOpenChange={setShowMembershipDeleteError}
        title="Remove Failed"
        description="Failed to remove membership."
        buttonLabel="OK"
        variant="error"
      />
    </div>
  );
}
