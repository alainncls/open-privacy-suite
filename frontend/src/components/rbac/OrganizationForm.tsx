import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertCircle, Save, X, Loader2 } from 'lucide-react';

interface OrganizationFormProps {
  organization?: Organization;
  onClose: () => void;
  onSave: () => void;
}

export default function OrganizationForm({
  organization,
  onClose,
  onSave,
}: OrganizationFormProps) {
  const [name, setName] = useState(organization?.name || '');
  const [slug, setSlug] = useState(organization?.slug || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-generate slug from name (only for new orgs)
  const handleNameChange = (value: string) => {
    setName(value);
    if (!organization) {
      const generatedSlug = value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');
      setSlug(generatedSlug);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      if (organization) {
        await rbacApi.orgs.update(organization.id, { name, slug });
      } else {
        await rbacApi.orgs.create({ name, slug });
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save organization:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save organization. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
          <span className="text-[#991B1B] text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">Name</label>
        <Input
          type="text"
          value={name}
          onChange={e => handleNameChange(e.target.value)}
          placeholder="e.g., Acme Corporation"
          required
        />
        <p className="text-xs text-[#94A3B8]">Display name for the organization</p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-[#374151]">Slug</label>
        <Input
          type="text"
          value={slug}
          onChange={e => setSlug(e.target.value)}
          placeholder="e.g., acme-corp"
          required
          pattern="^[a-z0-9]+(-[a-z0-9]+)*$"
          title="Lowercase letters, numbers, and hyphens only"
        />
        <p className="text-xs text-[#94A3B8]">
          URL-friendly identifier (lowercase, hyphens allowed)
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
              {organization ? 'Update' : 'Create'} Organization
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
