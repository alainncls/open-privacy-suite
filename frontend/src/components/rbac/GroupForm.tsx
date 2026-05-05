import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { AlertCircle, Save, X, Loader2, Shield, Check } from 'lucide-react';

interface GroupFormProps {
  orgId: string;
  groups?: Group[]; // kept for API compat but unused (no parent hierarchy)
  group?: Group;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupForm({
  orgId,
  group,
  onClose,
  onSave,
}: GroupFormProps) {
  const [name, setName] = useState(group?.name || '');
  const [slug, setSlug] = useState(group?.slug || '');
  const [description, setDescription] = useState(group?.description || '');
  const [isOrgAdmin, setIsOrgAdmin] = useState(group?.is_org_admin || false);
  const [isOrgReadonlyAdmin, setIsOrgReadonlyAdmin] = useState(group?.is_org_readonly_admin || false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!group;

  // Auto-generate slug from name (only for new groups)
  const handleNameChange = (value: string) => {
    setName(value);
    if (!isEditing) {
      const generatedSlug = value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_|_$/g, '');
      setSlug(generatedSlug);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      if (isEditing) {
        await rbacApi.groups.update(orgId, group.id, {
          name,
          description,
          is_org_admin: isOrgAdmin,
          is_org_readonly_admin: isOrgReadonlyAdmin,
        });
      } else {
        await rbacApi.groups.create(orgId, {
          slug,
          name,
          description,
          parent_id: null,
          is_org_admin: isOrgAdmin,
          is_org_readonly_admin: isOrgReadonlyAdmin,
        });
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save group:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save group. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Name</label>
        <Input
          type="text"
          value={name}
          onChange={e => handleNameChange(e.target.value)}
          placeholder="e.g., Engineering, DevOps, Auditors"
          required
        />
      </div>

      {!isEditing && (
        <div className="space-y-2">
          <label className="block text-sm font-medium text-neutral-700">Slug</label>
          <Input
            type="text"
            value={slug}
            onChange={e => setSlug(e.target.value)}
            placeholder="e.g., engineering"
            required
            pattern="^[a-z0-9]+(_[a-z0-9]+)*$"
            title="Lowercase letters, numbers, and underscores only"
          />
          <p className="text-xs text-neutral-400">
            URL-friendly identifier (lowercase, underscores allowed)
          </p>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          Description (optional)
        </label>
        <Textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="Describe the purpose of this group..."
          className="h-20"
        />
      </div>

      {/* Organization Admin Toggle */}
      <div className="space-y-2">
        <label
          className="flex items-start gap-3 p-3 rounded-lg bg-warning-light border border-warning/40 cursor-pointer hover:bg-yellow-200 transition-colors"
          onClick={() => {
            setIsOrgAdmin(!isOrgAdmin);
            if (!isOrgAdmin) setIsOrgReadonlyAdmin(false);
          }}
        >
          <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
            isOrgAdmin
              ? 'bg-warning border-warning'
              : 'border-neutral-300 bg-white'
          }`}>
            {isOrgAdmin && <Check className="w-3 h-3 text-white" />}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-warning-dark" />
              <span className="text-sm font-medium text-warning-dark">Organization Admin</span>
            </div>
            <p className="text-xs text-neutral-500 mt-1">
              Members of this group get the admin claim (which implies deploy and upgrade) on all contracts in the organization. Use with caution.
            </p>
          </div>
        </label>
      </div>

      {/* Read-only Admin Toggle */}
      <div className="space-y-2">
        <label
          className="flex items-start gap-3 p-3 rounded-lg bg-primary-50 border border-primary-200 cursor-pointer hover:bg-primary-100 transition-colors"
          onClick={() => {
            setIsOrgReadonlyAdmin(!isOrgReadonlyAdmin);
            if (!isOrgReadonlyAdmin) setIsOrgAdmin(false);
          }}
        >
          <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
            isOrgReadonlyAdmin
              ? 'bg-primary border-primary'
              : 'border-neutral-300 bg-white'
          }`}>
            {isOrgReadonlyAdmin && <Check className="w-3 h-3 text-white" />}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary-700" />
              <span className="text-sm font-medium text-primary-700">Read-only Org Admin</span>
            </div>
            <p className="text-xs text-neutral-500 mt-1">
              Members get read-only access to the admin dashboard (auditor role). They cannot modify settings or resources.
            </p>
          </div>
        </label>
      </div>

      <div className="p-3 rounded-lg bg-neutral-50 border border-neutral-200">
        <p className="text-sm text-neutral-600">
          <strong>Tip:</strong> After creating the group, use the settings icon to configure
          allowed RPC methods, claims, and rate limits.
        </p>
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <Button
          type="button"
          variant="ghost"
          onClick={onClose}
          disabled={saving}
          className="gap-2"
        >
          <X className="w-4 h-4" />
          Cancel
        </Button>
        <Button type="submit" disabled={saving} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {isEditing ? 'Update' : 'Create'} Group
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
