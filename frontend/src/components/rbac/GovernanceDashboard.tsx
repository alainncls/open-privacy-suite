import React, { useEffect, useState } from 'react';
import { useOrgContext } from './RBACManager';
import { rbacApi } from '@/api/rbac';
import type { ApprovalRequest, GovernanceApproverGroup, GroupWithAccess } from '@/types/rbac';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Loader2, Save, CheckCircle2, XCircle, AlertCircle, Clock } from 'lucide-react';

export default function GovernanceDashboard() {
  const { selectedOrg, refreshOrgs } = useOrgContext();
  
  // Settings Form State
  const [enabled, setEnabled] = useState(false);
  const [threshold, setThreshold] = useState(1);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  
  // Requests State
  const [requests, setRequests] = useState<ApprovalRequest[]>([]);
  const [loadingRequests, setLoadingRequests] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Approver Groups State
  const [approverGroups, setApproverGroups] = useState<GovernanceApproverGroup[]>([]);
  const [allGroups, setAllGroups] = useState<GroupWithAccess[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [addingApproverGroup, setAddingApproverGroup] = useState(false);
  const [removingGroupId, setRemovingGroupId] = useState<string | null>(null);
  const [approverError, setApproverError] = useState<string | null>(null);

  useEffect(() => {
    if (selectedOrg) {
      setEnabled(selectedOrg.governance_enabled ?? false);
      setThreshold(selectedOrg.approval_threshold ?? 1);
      setWebhookUrl(selectedOrg.governance_webhook_url ?? '');
      loadRequests(selectedOrg.id);
      loadApproverGroups(selectedOrg.id);
      loadAllGroups(selectedOrg.id);
    }
  }, [selectedOrg]);

  const loadRequests = async (orgId: string) => {
    setLoadingRequests(true);
    setActionError(null);
    try {
      // Only fetch pending requests by default
      const res = await rbacApi.governance.listRequests(orgId, { status: 'pending', limit: 50 });
      setRequests(res.data.data || []);
    } catch (err) {
      console.error('Failed to load governance requests', err);
    } finally {
      setLoadingRequests(false);
    }
  };

  const loadApproverGroups = async (orgId: string) => {
    try {
      const res = await rbacApi.governance.listApproverGroups(orgId);
      setApproverGroups(res.data.data || []);
    } catch (err) {
      console.error('Failed to load approver groups', err);
    }
  };

  const loadAllGroups = async (orgId: string) => {
    try {
      const res = await rbacApi.groups.list(orgId, { limit: 100 });
      setAllGroups(res.data.data || []);
    } catch (err) {
      console.error('Failed to load groups', err);
    }
  };

  const handleAddApproverGroup = async () => {
    if (!selectedOrg || !selectedGroupId) return;
    setAddingApproverGroup(true);
    setApproverError(null);
    try {
      await rbacApi.governance.addApproverGroup(selectedOrg.id, selectedGroupId);
      setSelectedGroupId('');
      // In production, adding an approver might trigger a governance request itself.
      // Reload both tables to be safe (if auto-approved, it appears in Approvers, else in Requests)
      await loadApproverGroups(selectedOrg.id);
      await loadRequests(selectedOrg.id);
    } catch (err: any) {
      setApproverError(err.response?.data?.error || 'Failed to add approver group');
    } finally {
      setAddingApproverGroup(false);
    }
  };

  const handleRemoveApproverGroup = async (groupId: string) => {
    if (!selectedOrg) return;
    setRemovingGroupId(groupId);
    setApproverError(null);
    try {
      await rbacApi.governance.removeApproverGroup(selectedOrg.id, groupId);
      await loadApproverGroups(selectedOrg.id);
      await loadRequests(selectedOrg.id);
    } catch (err: any) {
      setApproverError(err.response?.data?.error || 'Failed to remove approver group');
    } finally {
      setRemovingGroupId(null);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrg) return;
    
    setSavingSettings(true);
    setSettingsError(null);
    try {
      await rbacApi.governance.updateSettings(selectedOrg.id, {
        governance_enabled: enabled,
        approval_threshold: threshold,
        governance_webhook_url: webhookUrl
      });
      await refreshOrgs(); // refresh context
    } catch (err: any) {
      setSettingsError(err.response?.data?.error || 'Failed to update settings');
    } finally {
      setSavingSettings(false);
    }
  };

  const handleDecision = async (reqId: string, decision: 'approve' | 'reject') => {
    if (!selectedOrg) return;
    
    setActionLoading(reqId);
    setActionError(null);
    try {
      if (decision === 'approve') {
        await rbacApi.governance.approve(selectedOrg.id, reqId, 'Approved via dashboard');
      } else {
        await rbacApi.governance.reject(selectedOrg.id, reqId, 'Rejected via dashboard');
      }
      await loadRequests(selectedOrg.id);
    } catch (err: any) {
      setActionError(err.response?.data?.error || `Failed to ${decision} request`);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Settings Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Governance Settings</CardTitle>
          <CardDescription>
            Configure multi-party approval requirements for sensitive RBAC mutations.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {settingsError && (
            <div className="mb-4 p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-error-dark" />
              <span className="text-error-dark text-sm">{settingsError}</span>
            </div>
          )}
          <form onSubmit={handleSaveSettings} className="space-y-4 max-w-xl">
            <div className="flex items-center gap-3">
              <input 
                type="checkbox" 
                id="gov-enabled"
                checked={enabled}
                onChange={e => setEnabled(e.target.checked)}
                className="w-4 h-4 text-primary rounded border-neutral-300 focus:ring-primary"
              />
              <label htmlFor="gov-enabled" className="text-sm font-medium text-neutral-700">
                Enable Governance Approvals
              </label>
            </div>
            
            <div className="space-y-2">
              <label htmlFor="approval-threshold" className="block text-sm font-medium text-neutral-700">Approval Threshold</label>
              <Input
                id="approval-threshold"
                type="number"
                min={1}
                max={10}
                value={threshold}
                onChange={e => setThreshold(parseInt(e.target.value) || 1)}
                disabled={!enabled}
                className="w-32"
              />
              <p className="text-xs text-neutral-500">Number of distinct admin approvals required.</p>
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-neutral-700">Webhook Notification URL</label>
              <Input
                type="url"
                value={webhookUrl}
                onChange={e => setWebhookUrl(e.target.value)}
                disabled={!enabled}
                placeholder="https://hooks.slack.com/services/..."
              />
              <p className="text-xs text-neutral-500">Optional. Receive alerts when new requests are pending.</p>
            </div>

            <Button type="submit" disabled={savingSettings} className="gap-2 mt-2">
              {savingSettings ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Save Settings
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Approver Groups Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Approver Groups</CardTitle>
          <CardDescription>
            Designate which RBAC groups are permitted to approve governance requests. 
            {approverGroups.length === 0 && " If none are specified, any organization admin can approve."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {approverError && (
            <div className="mb-4 p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-error-dark" />
              <span className="text-error-dark text-sm">{approverError}</span>
            </div>
          )}
          
          <div className="flex gap-2 mb-6">
            <select
              className="flex h-10 w-full md:w-64 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background disabled:cursor-not-allowed disabled:opacity-50"
              value={selectedGroupId}
              onChange={(e) => setSelectedGroupId(e.target.value)}
              disabled={!enabled}
            >
              <option value="">Select a group...</option>
              {allGroups.filter(g => !approverGroups.some(ag => ag.group_id === g.group.id)).map(g => (
                <option key={g.group.id} value={g.group.id}>
                  {g.group.name}
                </option>
              ))}
            </select>
            <Button 
              onClick={handleAddApproverGroup}
              disabled={!selectedGroupId || addingApproverGroup || !enabled}
            >
              {addingApproverGroup ? <Loader2 className="w-4 h-4 animate-spin" /> : "Add Group"}
            </Button>
          </div>

          <div className="space-y-3">
            {approverGroups.map(ag => (
              <div key={ag.id} className="flex items-center justify-between p-3 border rounded-lg bg-neutral-50/50">
                <div className="flex items-center gap-3">
                  <span className="font-medium text-neutral-800">{ag.group_name}</span>
                  <Badge variant="outline" className="text-xs bg-white">
                    {ag.group_slug}
                  </Badge>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-error hover:bg-error-50 hover:text-error-dark h-8 px-2"
                  onClick={() => handleRemoveApproverGroup(ag.group_id)}
                  disabled={removingGroupId === ag.group_id || !enabled}
                >
                  {removingGroupId === ag.group_id ? <Loader2 className="w-4 h-4 animate-spin" /> : <XCircle className="w-4 h-4 mr-1" />}
                  Remove
                </Button>
              </div>
            ))}
            {approverGroups.length === 0 && (
              <div className="text-center py-6 border border-dashed rounded-lg text-neutral-500 text-sm">
                No dedicated approver groups configured.
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Pending Requests Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Pending Approvals</CardTitle>
          <CardDescription>
            Review and vote on pending RBAC mutations in this organization.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {actionError && (
            <div className="mb-4 p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-error-dark" />
              <span className="text-error-dark text-sm">{actionError}</span>
            </div>
          )}

          {loadingRequests ? (
            <div className="flex justify-center py-8">
              <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
            </div>
          ) : requests.length === 0 ? (
            <div className="text-center py-8 bg-neutral-50 rounded-lg border border-neutral-100">
              <CheckCircle2 className="w-8 h-8 text-neutral-300 mx-auto mb-2" />
              <p className="text-neutral-500 text-sm">No pending requests at this time.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {requests.map(req => (
                <div key={req.id} className="p-4 border border-neutral-200 rounded-lg flex flex-col md:flex-row gap-4 justify-between items-start md:items-center bg-white shadow-sm">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="bg-primary-50 text-primary-700 border-primary-200">
                        {req.change_type}
                      </Badge>
                      <span className="text-xs text-neutral-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(req.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div>
                      <span className="text-sm font-medium text-neutral-700">Target: </span>
                      <code className="text-xs bg-neutral-100 px-1.5 py-0.5 rounded text-neutral-600">
                        {req.target_resource_type}
                      </code>
                    </div>
                    <div className="text-xs text-neutral-500 font-mono bg-neutral-50 p-2 rounded max-h-24 overflow-y-auto mt-2">
                      {JSON.stringify(req.payload, null, 2)}
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2 shrink-0">
                    <Button 
                      variant="outline" 
                      className="gap-1 border-error text-error hover:bg-error-50"
                      size="sm"
                      onClick={() => handleDecision(req.id, 'reject')}
                      disabled={actionLoading !== null}
                    >
                      {actionLoading === req.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <XCircle className="w-3.5 h-3.5" />}
                      Reject
                    </Button>
                    <Button 
                      className="gap-1 bg-success hover:bg-success-600 text-white"
                      size="sm"
                      onClick={() => handleDecision(req.id, 'approve')}
                      disabled={actionLoading !== null}
                    >
                      {actionLoading === req.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                      Approve
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
