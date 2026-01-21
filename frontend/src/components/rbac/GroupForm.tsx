import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, Role } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertCircle, Save, X, Loader2, FolderTree, Shield } from 'lucide-react';

interface GroupFormProps {
  orgId: string;
  groups: Group[];
  roles?: Role[];
  group?: Group;
  parentId?: string;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupForm({
  orgId,
  groups,
  roles: propRoles,
  group,
  parentId,
  onClose,
  onSave,
}: GroupFormProps) {
  const [name, setName] = useState(group?.name || '');
  const [slug, setSlug] = useState(group?.slug || '');
  const [description, setDescription] = useState(group?.description || '');
  const [selectedParentId, setSelectedParentId] = useState<string | undefined>(
    parentId || group?.parent_id || undefined
  );
  const [selectedRoleId, setSelectedRoleId] = useState<string | undefined>(
    group?.role_id || undefined
  );
  const [roles, setRoles] = useState<Role[]>(propRoles || []);
  const [loadingRoles, setLoadingRoles] = useState(!propRoles);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!group;

  useEffect(() => {
    if (!propRoles) {
      loadRoles();
    }
  }, [orgId, propRoles]);

  const loadRoles = async () => {
    try {
      setLoadingRoles(true);
      const response = await rbacApi.roles.list(orgId);
      setRoles(response.data || []);
    } catch (error) {
      console.error('Failed to load roles:', error);
      setRoles([]);
    } finally {
      setLoadingRoles(false);
    }
  };

  // Filter out the current group and its descendants from parent options
  const getAvailableParents = () => {
    if (!group) return groups;

    // Get all descendant IDs
    const descendants = new Set<string>();
    const findDescendants = (id: string) => {
      descendants.add(id);
      groups.filter(g => g.parent_id === id).forEach(g => findDescendants(g.id));
    };
    findDescendants(group.id);

    return groups.filter(g => !descendants.has(g.id));
  };

  const availableParents = getAvailableParents();

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
          role_id: selectedRoleId || null,
        });
      } else {
        await rbacApi.groups.create(orgId, {
          slug,
          name,
          description,
          parent_id: selectedParentId || null,
          role_id: selectedRoleId || null,
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

  const selectedParent = selectedParentId
    ? groups.find(g => g.id === selectedParentId)
    : null;
  const previewPath = selectedParent
    ? `${selectedParent.path}.${slug || '<slug>'}`
    : slug || '<slug>';

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <span className="text-red-400 text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">Name</label>
        <Input
          type="text"
          value={name}
          onChange={e => handleNameChange(e.target.value)}
          placeholder="e.g., Engineering, DevOps, Auditors"
          required
        />
      </div>

      {!isEditing && (
        <>
          <div className="space-y-2">
            <label className="block text-sm font-medium text-white/70">Slug</label>
            <Input
              type="text"
              value={slug}
              onChange={e => setSlug(e.target.value)}
              placeholder="e.g., engineering"
              required
              pattern="^[a-z0-9]+(_[a-z0-9]+)*$"
              title="Lowercase letters, numbers, and underscores only"
            />
            <p className="text-xs text-white/40">
              URL-friendly identifier (lowercase, underscores allowed)
            </p>
          </div>

          <div className="space-y-2">
            <label className="block text-sm font-medium text-white/70">
              Parent Group (optional)
            </label>
            <Select
              value={selectedParentId || '_none'}
              onValueChange={value =>
                setSelectedParentId(value === '_none' ? undefined : value)
              }
            >
              <SelectTrigger>
                <SelectValue placeholder="No parent (root level)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="_none">
                  <div className="flex items-center gap-2 text-white/60">
                    <FolderTree className="w-4 h-4" />
                    <span>No parent (root level)</span>
                  </div>
                </SelectItem>
                {availableParents.map(g => (
                  <SelectItem key={g.id} value={g.id}>
                    <div className="flex items-center gap-2">
                      <FolderTree className="w-4 h-4 text-white/40" />
                      <span>{g.name}</span>
                      <span className="text-white/40 text-xs">({g.path})</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Path Preview */}
          <div className="p-3 rounded-lg bg-white/5 border border-white/10">
            <p className="text-xs text-white/50 mb-1">Path preview:</p>
            <code className="text-sm text-primary-400 font-mono">{previewPath}</code>
          </div>
        </>
      )}

      {/* Role Selector - always shown */}
      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Assigned Role
        </label>
        {loadingRoles ? (
          <div className="flex items-center gap-2 text-white/40 py-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Loading roles...</span>
          </div>
        ) : (
          <Select
            value={selectedRoleId || '_none'}
            onValueChange={value =>
              setSelectedRoleId(value === '_none' ? undefined : value)
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="No role assigned" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_none">
                <div className="flex items-center gap-2 text-white/60">
                  <Shield className="w-4 h-4" />
                  <span>No role assigned</span>
                </div>
              </SelectItem>
              {roles.map(role => (
                <SelectItem key={role.id} value={role.id}>
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-primary-400" />
                    <span>{role.name}</span>
                    {role.description && (
                      <span className="text-white/40 text-xs">- {role.description}</span>
                    )}
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <p className="text-xs text-white/40">
          All users in this group will inherit the selected role's permissions (methods + claims)
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-white/70">
          Description (optional)
        </label>
        <Textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="Describe the purpose of this group..."
          className="h-20"
        />
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
