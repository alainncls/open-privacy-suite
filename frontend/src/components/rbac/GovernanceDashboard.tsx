import React, { useEffect, useState } from 'react';
import { useOrgContext } from './RBACManager';
import { rbacApi } from '@/api/rbac';
import type { ApprovalRequest, ApprovalRequestWithDecisions, GovernanceApproverGroup, GroupWithAccess } from '@/types/rbac';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Loader2, Save, CheckCircle2, XCircle, AlertCircle, Clock, History, Filter } from 'lucide-react';

type RequestsTab = 'all' | 'awaiting_me' | 'history';

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
  const [requestsTab, setRequestsTab] = useState<RequestsTab>('all');

  // History State
  const [historyRequests, setHistoryRequests] = useState<ApprovalRequest[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [historyDetails, setHistoryDetails] = useState<Record<string, ApprovalRequestWithDecisions>>({});
  const [expandedHistoryId, setExpandedHistoryId] = useState<string | null>(null);

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
      loadRequests(selectedOrg.id, requestsTab);
      loadApproverGroups(selectedOrg.id);
      loadAllGroups(selectedOrg.id);
    }
  }, [selectedOrg]);

  useEffect(() => {
    if (selectedOrg) {
      if (requestsTab === 'history') {
        loadHistory(selectedOrg.id);
      } else {
        loadRequests(selectedOrg.id, requestsTab);
      }
    }
  }, [requestsTab, selectedOrg]);

  const loadRequests = async (orgId: string, tab: RequestsTab) => {
    if (tab === 'history') return;
    setLoadingRequests(true);
    setActionError(null);
    try {
      const params: { status?: string; limit?: number; awaiting_my_approval?: boolean } = {
        status: 'pending',
        limit: 50,
      };
      if (tab === 'awaiting_me') {
        params.awaiting_my_approval = true;
      }
      const res = await rbacApi.governance.listRequests(orgId, params);
      setRequests(res.data.data || []);
    } catch (err) {
      console.error('Failed to load governance requests', err);
    } finally {
      setLoadingRequests(false);
    }
  };

  const loadHistory = async (orgId: string) => {
    setLoadingHistory(true);
    try {
      // Fetch both approved and rejected requests
      const [approvedRes, rejectedRes] = await Promise.all([
        rbacApi.governance.listRequests(orgId, { status: 'approved', limit: 50 }),
        rbacApi.governance.listRequests(orgId, { status: 'rejected', limit: 50 }),
      ]);
      const approved = approvedRes.data.data || [];
      const rejected = rejectedRes.data.data || [];
      // Merge and sort by resolved_at descending
      const merged = [...approved, ...rejected].sort((a, b) => {
        const aTime = a.resolved_at ? new Date(a.resolved_at).getTime() : 0;
        const bTime = b.resolved_at ? new Date(b.resolved_at).getTime() : 0;
        return bTime - aTime;
      });
      setHistoryRequests(merged);
    } catch (err) {
      console.error('Failed to load history', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const loadRequestDetails = async (orgId: string, requestId: string) => {
    try {
      const res = await rbacApi.governance.getRequest(orgId, requestId);
      setHistoryDetails(prev => ({ ...prev, [requestId]: res.data }));
    } catch (err) {
      console.error('Failed to load request details', err);
    }
  };

  const toggleHistoryDetails = (requestId: string) => {
    if (expandedHistoryId === requestId) {
      setExpandedHistoryId(null);
    } else {
      setExpandedHistoryId(requestId);
      if (!historyDetails[requestId] && selectedOrg) {
        loadRequestDetails(selectedOrg.id, requestId);
      }
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
      await loadRequests(selectedOrg.id, requestsTab);
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
      await loadRequests(selectedOrg.id, requestsTab);
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
      await loadRequests(selectedOrg.id, requestsTab);
    } catch (err: any) {
      setActionError(err.response?.data?.error || `Failed to ${decision} request`);
    } finally {
      setActionLoading(null);
    }
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case 'approved':
        return <Badge className="bg-success/10 text-success border-success/20"><CheckCircle2 className="w-3 h-3 mr-1" />Approved</Badge>;
      case 'rejected':
        return <Badge className="bg-error/10 text-error border-error/20"><XCircle className="w-3 h-3 mr-1" />Rejected</Badge>;
      default:
        return <Badge variant="outline"><Clock className="w-3 h-3 mr-1" />{status}</Badge>;
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

      {/* Requests Card with Tabs */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg">Approval Requests</CardTitle>
              <CardDescription>
                Review and vote on RBAC mutations in this organization.
              </CardDescription>
            </div>
          </div>
          {/* Tab Navigation */}
          <div className="flex gap-1 mt-3 border-b border-neutral-200" data-testid="governance-request-tabs">
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                requestsTab === 'all'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-neutral-500 hover:text-neutral-700'
              }`}
              onClick={() => setRequestsTab('all')}
              data-testid="tab-all-requests"
            >
              All Pending
            </button>
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                requestsTab === 'awaiting_me'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-neutral-500 hover:text-neutral-700'
              }`}
              onClick={() => setRequestsTab('awaiting_me')}
              data-testid="tab-awaiting-my-approval"
            >
              <Filter className="w-3.5 h-3.5" />
              Awaiting My Approval
            </button>
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                requestsTab === 'history'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-neutral-500 hover:text-neutral-700'
              }`}
              onClick={() => setRequestsTab('history')}
              data-testid="tab-history"
            >
              <History className="w-3.5 h-3.5" />
              History
            </button>
          </div>
        </CardHeader>
        <CardContent>
          {actionError && (
            <div className="mb-4 p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-error-dark" />
              <span className="text-error-dark text-sm">{actionError}</span>
            </div>
          )}

          {/* Pending Requests (All / Awaiting Me) */}
          {requestsTab !== 'history' && (
            <>
              {loadingRequests ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
                </div>
              ) : requests.length === 0 ? (
                <div className="text-center py-8 bg-neutral-50 rounded-lg border border-neutral-100">
                  <CheckCircle2 className="w-8 h-8 text-neutral-300 mx-auto mb-2" />
                  <p className="text-neutral-500 text-sm">
                    {requestsTab === 'awaiting_me'
                      ? 'No requests awaiting your approval.'
                      : 'No pending requests at this time.'}
                  </p>
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
                          {req.escalated_at && (
                            <Badge className="bg-warning/10 text-warning border-warning/20 text-xs">
                              <AlertCircle className="w-3 h-3 mr-1" />
                              Escalated
                            </Badge>
                          )}
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
            </>
          )}

          {/* History Tab */}
          {requestsTab === 'history' && (
            <>
              {loadingHistory ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
                </div>
              ) : historyRequests.length === 0 ? (
                <div className="text-center py-8 bg-neutral-50 rounded-lg border border-neutral-100">
                  <History className="w-8 h-8 text-neutral-300 mx-auto mb-2" />
                  <p className="text-neutral-500 text-sm">No resolved requests yet.</p>
                </div>
              ) : (
                <div className="space-y-3" data-testid="history-list">
                  {historyRequests.map(req => (
                    <div key={req.id} className="border border-neutral-200 rounded-lg bg-white shadow-sm">
                      <button
                        className="w-full p-4 flex flex-col md:flex-row gap-3 justify-between items-start md:items-center text-left"
                        onClick={() => toggleHistoryDetails(req.id)}
                        data-testid="history-row"
                      >
                        <div className="flex items-center gap-3 flex-wrap">
                          {statusBadge(req.status)}
                          <Badge variant="outline" className="bg-primary-50 text-primary-700 border-primary-200">
                            {req.change_type}
                          </Badge>
                          <span className="text-xs text-neutral-500">
                            Requester: <code className="bg-neutral-100 px-1 rounded">{req.requester_id.slice(0, 8)}...</code>
                          </span>
                        </div>
                        <span className="text-xs text-neutral-500 flex items-center gap-1 shrink-0">
                          <Clock className="w-3 h-3" />
                          {req.resolved_at ? new Date(req.resolved_at).toLocaleString() : 'N/A'}
                        </span>
                      </button>

                      {expandedHistoryId === req.id && (
                        <div className="border-t border-neutral-100 p-4 bg-neutral-50/50">
                          <div className="text-xs text-neutral-500 font-mono bg-white p-2 rounded border max-h-32 overflow-y-auto mb-3">
                            {JSON.stringify(req.payload, null, 2)}
                          </div>
                          {historyDetails[req.id]?.decisions ? (
                            <div className="space-y-2">
                              <p className="text-xs font-medium text-neutral-600">Decisions:</p>
                              {historyDetails[req.id].decisions.map(dec => (
                                <div key={dec.id} className="flex items-center gap-2 text-xs">
                                  {dec.decision === 'approve' ? (
                                    <CheckCircle2 className="w-3.5 h-3.5 text-success" />
                                  ) : (
                                    <XCircle className="w-3.5 h-3.5 text-error" />
                                  )}
                                  <code className="bg-neutral-100 px-1 rounded">{dec.approver_id.slice(0, 8)}...</code>
                                  <span className="text-neutral-500">
                                    {dec.decision === 'approve' ? 'approved' : 'rejected'}
                                    {dec.reason && ` - "${dec.reason}"`}
                                  </span>
                                  <span className="text-neutral-400 ml-auto">
                                    {new Date(dec.decided_at).toLocaleString()}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="flex items-center gap-2 text-xs text-neutral-400">
                              <Loader2 className="w-3 h-3 animate-spin" />
                              Loading decisions...
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
