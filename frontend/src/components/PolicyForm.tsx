import { useState } from 'react';
import { policiesApi, AccessPolicy } from '../api/client';

interface PolicyFormProps {
  policy?: AccessPolicy;
  onClose: () => void;
  onSave: () => void;
}

function PolicyForm({ policy, onClose, onSave }: PolicyFormProps) {
  const [externalId, setExternalId] = useState(policy?.external_id || '');
  const [kyc, setKyc] = useState(policy?.kyc ?? true);
  const [methods, setMethods] = useState(
    policy?.allow_methods && policy.allow_methods.length > 0 
      ? policy.allow_methods.join(', ') 
      : ''
  );
  const [banned, setBanned] = useState(policy?.banned ?? false);
  const [note, setNote] = useState(policy?.note || '');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    try {
      const allowMethods = methods
        .split(',')
        .map(m => m.trim())
        .filter(m => m.length > 0);

      const policyData: AccessPolicy = {
        external_id: externalId,
        kyc,
        allow_methods: allowMethods,
        banned,
        note: note || undefined,
      };

      try {
        if (policy) {
          await policiesApi.update(externalId, policyData);
        } else {
          await policiesApi.create(policyData);
        }

        // Close form first, then reload
        onSave();
      } catch (error: any) {
        console.error('Failed to save policy:', error);
        if (error.response) {
          console.error('Response error:', error.response.status, error.response.data);
          alert(`Failed to save policy: ${error.response.data?.error || error.message}`);
        } else {
          alert('Failed to save policy. Check console for details.');
        }
        throw error; // Re-throw to be caught by outer catch
      }
    } catch (error) {
      console.error('Failed to save policy:', error);
      alert('Failed to save policy. Check console for details.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
    }}>
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '8px',
        maxWidth: '500px',
        width: '90%',
        maxHeight: '90vh',
        overflow: 'auto',
      }}>
        <h3>{policy ? 'Edit Policy' : 'Create Policy'}</h3>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1rem' }}>
            <label>
              External ID (e.g., billions:user_123)
              <input
                type="text"
                value={externalId}
                onChange={(e) => setExternalId(e.target.value)}
                required
                disabled={!!policy}
                style={{ width: '100%', padding: '0.5rem', marginTop: '0.25rem' }}
              />
            </label>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label>
              <input
                type="checkbox"
                checked={kyc}
                onChange={(e) => setKyc(e.target.checked)}
              />
              KYC Verified
            </label>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label>
              Allowed Methods (comma-separated)
              <input
                type="text"
                value={methods}
                onChange={(e) => setMethods(e.target.value)}
                placeholder="eth_call, eth_getBalance"
                style={{ width: '100%', padding: '0.5rem', marginTop: '0.25rem' }}
              />
            </label>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label>
              <input
                type="checkbox"
                checked={banned}
                onChange={(e) => setBanned(e.target.checked)}
              />
              Banned
            </label>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label>
              Note
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                style={{ width: '100%', padding: '0.5rem', marginTop: '0.25rem', minHeight: '60px' }}
              />
            </label>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose} disabled={saving}>
              Cancel
            </button>
            <button type="submit" disabled={saving}>
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default PolicyForm;
