import { useEffect, useState } from 'react';
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
import {
  Shield,
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
}

export default function UserDetail({ user, onUpdate }: UserDetailProps) {
  const { organizations, selectedOrg } = useOrgContext();
  const [memberships, setMemberships] = useState<MembershipWithDetails[]>([]);
  const [effectivePerms, setEffectivePerms] = useState<EffectivePermissions | null>(null);
  const [linkedAddresses, setLinkedAddresses] = useState<LinkedAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingAddresses, setLoadingAddresses] = useState(true);
  const [showMembershipForm, setShowMembershipForm] = useState(false);

  // ENS name resolution for linked addresses
  const { data: ensNames, isLoading: loadingEns } = useEnsNames(
    linkedAddresses.map(a => a.address)
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
    if (selectedOrg) {
      loadEffectivePermissions();
    }
  }, [user.id, selectedOrg]);

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

  const loadEffectivePermissions = async () => {
    if (!selectedOrg) return;
    try {
      const response = await rbacApi.users.getEffectivePermissions(
        user.id,
        selectedOrg.slug
      );
      setEffectivePerms(response.data);
    } catch {
      setEffectivePerms(null);
    }
  };

  const handleDeleteMembership = async (membershipId: string) => {
    if (!confirm('Remove this membership?')) return;
    try {
      await rbacApi.users.deleteMembership(user.id, membershipId);
      await loadMemberships();
      await loadEffectivePermissions();
      onUpdate();
    } catch (error) {
      console.error('Failed to delete membership:', error);
      alert('Failed to remove membership.');
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
    await loadEffectivePermissions();
    onUpdate();
  };

  const getClaimColor = (claim: string) => {
    switch (claim) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'deployer':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'upgrade':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'writer':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'reader':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-white/10 text-white/60 border-white/20';
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <span className="text-red-400 text-sm">{error}</span>
        </div>
      )}

      {/* User Info */}
      <div className="p-4 rounded-lg bg-white/5 space-y-4">
        <h4 className="text-sm font-medium text-white/70">User Information</h4>

        <div className="space-y-2">
          <label className="block text-xs text-white/50">External ID (DID)</label>
          <Input
            value={user.external_id}
            disabled
            className="font-mono text-sm bg-white/5"
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
              <div className="w-5 h-5 rounded border border-white/20 bg-white/5 peer-checked:bg-green-500 peer-checked:border-green-500 transition-all flex items-center justify-center">
                {kyc && (
                  <Check className="w-3 h-3 text-white" />
                )}
              </div>
            </div>
            <span className="text-sm text-white/80 group-hover:text-white/90 transition-colors">
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
              <div className="w-5 h-5 rounded border border-white/20 bg-white/5 peer-checked:bg-red-500 peer-checked:border-red-500 transition-all flex items-center justify-center">
                {banned && (
                  <X className="w-3 h-3 text-white" />
                )}
              </div>
            </div>
            <span className="text-sm text-white/80 group-hover:text-white/90 transition-colors">
              Banned
            </span>
          </label>
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-white/50">Note</label>
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
        <h4 className="text-sm font-medium text-white/70 flex items-center gap-2">
          <Wallet className="w-4 h-4" />
          Linked Wallet Addresses
        </h4>

        {loadingAddresses ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-5 h-5 text-white/40 animate-spin" />
          </div>
        ) : linkedAddresses.length === 0 ? (
          <div className="text-center py-6 text-white/40 text-sm">
            No linked wallet addresses
          </div>
        ) : (
          <div className="space-y-2">
            {linkedAddresses.map((addr) => (
              <div
                key={addr.address}
                className="flex items-center justify-between p-3 rounded-lg bg-white/5"
              >
                <AddressDisplay
                  address={addr.address}
                  ensName={ensNames?.[addr.address.toLowerCase()]}
                />
                <div className="flex items-center gap-2">
                  {loadingEns && !ensNames?.[addr.address.toLowerCase()] && (
                    <Loader2 className="w-3 h-3 text-white/30 animate-spin" />
                  )}
                  <span className="text-xs text-white/40">
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
          <h4 className="text-sm font-medium text-white/70">Group Memberships</h4>
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
            <Loader2 className="w-5 h-5 text-white/40 animate-spin" />
          </div>
        ) : memberships.length === 0 ? (
          <div className="text-center py-6 text-white/40 text-sm">
            No group memberships
          </div>
        ) : (
          <div className="space-y-2">
            {memberships.map((m, idx) => (
              <div
                key={m.membership?.id || idx}
                className="flex items-center justify-between p-3 rounded-lg bg-white/5"
              >
                <div className="flex items-center gap-3">
                  <FolderTree className="w-4 h-4 text-primary-400" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{m.group?.name || 'Unknown Group'}</span>
                      <Badge variant="outline" className="text-xs font-mono">
                        {m.group?.path || 'N/A'}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      {m.role ? (
                        <Badge variant="secondary" className="text-xs gap-1">
                          <Shield className="w-3 h-3" />
                          {m.role.name}
                          {m.group?.role_id ? ' (from group)' : ' (legacy)'}
                        </Badge>
                      ) : (
                        <span className="text-xs text-white/40">No role assigned</span>
                      )}
                      {m.membership?.source && (
                        <Badge
                          variant="outline"
                          className={`text-xs ${
                            m.membership.source === 'zk_attested'
                              ? 'text-purple-400 border-purple-500/30'
                              : 'text-white/50'
                          }`}
                        >
                          {m.membership.source}
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
                {m.membership?.id && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDeleteMembership(m.membership.id)}
                    className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                    title="Remove membership"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Effective Permissions */}
      {selectedOrg && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-white/70">
            Effective Permissions ({selectedOrg.name})
          </h4>

          {effectivePerms ? (
            <div className="p-4 rounded-lg bg-white/5 space-y-4">
              <div>
                <label className="text-xs text-white/50 mb-1 block">Claims</label>
                {effectivePerms.claims && effectivePerms.claims.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {effectivePerms.claims.map(claim => (
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
                  <span className="text-white/40 text-sm">None</span>
                )}
              </div>

              <div>
                <label className="text-xs text-white/50 mb-1 block">
                  Allowed Methods ({effectivePerms.allow_methods?.length || 0})
                </label>
                {effectivePerms.allow_methods && effectivePerms.allow_methods.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {effectivePerms.allow_methods.slice(0, 10).map(method => (
                      <Badge key={method} variant="outline" className="text-xs font-mono">
                        {method}
                      </Badge>
                    ))}
                    {effectivePerms.allow_methods.length > 10 && (
                      <Badge variant="secondary" className="text-xs">
                        +{effectivePerms.allow_methods.length - 10} more
                      </Badge>
                    )}
                  </div>
                ) : (
                  <span className="text-white/40 text-sm">None</span>
                )}
              </div>

              <div className="flex gap-4">
                <div>
                  <label className="text-xs text-white/50 mb-1 block">Rate Limit (RPS)</label>
                  <span className="text-sm">
                    {effectivePerms.rate_limit_rps ?? 'Unlimited'}
                  </span>
                </div>
                <div>
                  <label className="text-xs text-white/50 mb-1 block">Rate Limit (Daily)</label>
                  <span className="text-sm">
                    {effectivePerms.rate_limit_daily ?? 'Unlimited'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-6 text-white/40 text-sm">
              No permissions in this organization
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
            onClose={() => setShowMembershipForm(false)}
            onSave={handleMembershipSave}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
