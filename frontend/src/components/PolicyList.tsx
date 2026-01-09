import { useEffect, useState } from 'react';
import { policiesApi, AccessPolicy } from '../api/client';
import PolicyForm from './PolicyForm';

function PolicyList() {
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      setLoading(true);
      const response = await policiesApi.list();
      const policies = response.data || [];
      console.log('Loaded policies:', policies);
      // Validate that all policies have external_id
      const validPolicies = policies.filter((p: AccessPolicy) => {
        if (!p.external_id) {
          console.warn('Policy missing external_id:', p);
          return false;
        }
        return true;
      });
      setPolicies(validPolicies);
    } catch (error: any) {
      console.error('Failed to load policies:', error);
      // Show error but don't crash
      if (error.response) {
        console.error('Response error:', error.response.status, error.response.data);
      }
      setPolicies([]); // Set empty array on error
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (externalId: string) => {
    if (!confirm(`Delete policy for ${externalId}?`)) return;
    
    try {
      await policiesApi.delete(externalId);
      await loadPolicies();
    } catch (error) {
      console.error('Failed to delete policy:', error);
      alert('Failed to delete policy. Check console for details.');
    }
  };

  const handleToggleBan = async (policy: AccessPolicy) => {
    if (!policy?.external_id) {
      console.error('Policy missing external_id:', policy);
      alert('Error: Policy is missing external_id');
      return;
    }
    try {
      await policiesApi.update(policy.external_id, { banned: !policy.banned });
      await loadPolicies();
    } catch (error: any) {
      console.error('Failed to update policy:', error);
      if (error.response) {
        console.error('Response error:', error.response.status, error.response.data);
        alert(`Failed to update policy: ${error.response.data?.error || error.message}`);
      } else {
        alert('Failed to update policy. Check console for details.');
      }
    }
  };

  if (loading) {
    return <div>Loading policies...</div>;
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>Access Policies</h2>
        <button onClick={() => setShowForm(true)}>+ Add Policy</button>
      </div>

      {showForm && (
        <PolicyForm
          onClose={() => {
            setShowForm(false);
            setEditing(null);
          }}
          onSave={async () => {
            setShowForm(false);
            setEditing(null);
            // Reload policies after form closes
            await loadPolicies();
          }}
        />
      )}

      {editing && (() => {
        const policyToEdit = policies.find(p => p.external_id === editing);
        console.log('Rendering edit form for:', editing, 'Found policy:', policyToEdit);
        if (!policyToEdit) {
          console.error('Policy not found for editing:', editing, 'Available policies:', policies.map(p => p.external_id));
          return <div>Error: Policy not found</div>;
        }
        return (
          <PolicyForm
            key={editing} // Force re-render when editing changes
            policy={policyToEdit}
            onClose={() => {
              setEditing(null);
              setShowForm(false);
            }}
            onSave={async () => {
              setEditing(null);
              setShowForm(false);
              // Reload policies after form closes
              await loadPolicies();
            }}
          />
        );
      })()}

      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '2px solid #ccc' }}>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>External ID</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>KYC</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Allowed Methods</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Status</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Note</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {policies.map((policy) => {
            // Debug: log policy to see what we're getting
            if (!policy.external_id) {
              console.error('Policy missing external_id:', policy);
            }
            return (
            <tr key={policy.external_id || 'unknown'} style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '0.5rem' }}>{policy.external_id || 'N/A'}</td>
              <td style={{ padding: '0.5rem' }}>
                {policy.kyc ? '✓' : '✗'}
              </td>
              <td style={{ padding: '0.5rem' }}>
                {policy.allow_methods && policy.allow_methods.length > 0 
                  ? policy.allow_methods.join(', ') 
                  : 'none'}
              </td>
              <td style={{ padding: '0.5rem' }}>
                <span style={{ color: policy.banned ? 'red' : 'green' }}>
                  {policy.banned ? 'Banned' : 'Active'}
                </span>
              </td>
              <td style={{ padding: '0.5rem' }}>{policy.note || '-'}</td>
              <td style={{ padding: '0.5rem' }}>
                <button
                  onClick={() => handleToggleBan(policy)}
                  style={{ marginRight: '0.5rem' }}
                >
                  {policy.banned ? 'Unban' : 'Ban'}
                </button>
                <button 
                  onClick={() => {
                    if (!policy?.external_id) {
                      console.error('Policy missing external_id:', policy);
                      alert('Error: Policy is missing external_id');
                      return;
                    }
                    console.log('Editing policy:', policy.external_id, policy);
                    setEditing(policy.external_id);
                    setShowForm(false);
                  }}
                  style={{ marginRight: '0.5rem' }}
                >
                  Edit
                </button>
                <button 
                  onClick={() => handleDelete(policy.external_id)}
                  style={{ color: 'red' }}
                >
                  Delete
                </button>
              </td>
            </tr>
            );
          })}
        </tbody>
      </table>

      {policies.length === 0 && (
        <div style={{ padding: '2rem', textAlign: 'center', color: '#666' }}>
          No policies found. Create one to get started.
        </div>
      )}
    </div>
  );
}

export default PolicyList;
