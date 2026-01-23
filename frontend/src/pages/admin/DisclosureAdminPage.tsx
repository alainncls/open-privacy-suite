import { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Plus,
  RefreshCw,
  AlertCircle,
  FileText,
  Check,
  X,
  Clock,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { disclosureApi } from '@/api/disclosure';
import { CreateDisclosureRequestForm, DisclosureRequestCard } from '@/components/disclosure';
import type { DisclosureRequest, CreateDisclosureRequestInput } from '@/types/disclosure';
import { STATUS_LABELS, STATUS_VARIANTS } from '@/types/disclosure';

type TabValue = 'requests' | 'create';

export function DisclosureAdminPage() {
  const [activeTab, setActiveTab] = useState<TabValue>('requests');
  const [requests, setRequests] = useState<DisclosureRequest[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const loadRequests = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await disclosureApi.admin.listRequests(100);
      setRequests(response.data);
    } catch (err) {
      console.error('Failed to load disclosure requests:', err);
      setError('Failed to load disclosure requests. Make sure you are accessing from localhost.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRequests();
  }, [loadRequests]);

  const handleCreateRequest = async (input: CreateDisclosureRequestInput) => {
    setIsCreating(true);
    setError(null);
    setSuccessMessage(null);

    try {
      const response = await disclosureApi.admin.createRequest(input);
      setSuccessMessage(`Disclosure request created successfully (ID: ${response.data.id.slice(0, 8)}...)`);
      setActiveTab('requests');
      await loadRequests();
    } catch (err) {
      console.error('Failed to create disclosure request:', err);
      setError('Failed to create disclosure request. Please check the form and try again.');
    } finally {
      setIsCreating(false);
    }
  };

  // Group requests by status
  const pendingRequests = requests.filter((r) => r.status === 'pending');
  const approvedRequests = requests.filter((r) => r.status === 'approved');
  const rejectedRequests = requests.filter((r) => r.status === 'rejected');
  const revokedRequests = requests.filter((r) => r.status === 'revoked');
  const expiredRequests = requests.filter((r) => r.status === 'expired');

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return <Clock className="w-4 h-4" />;
      case 'approved':
        return <Check className="w-4 h-4" />;
      case 'rejected':
      case 'revoked':
        return <X className="w-4 h-4" />;
      default:
        return <FileText className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-white/95">Disclosure Management</h1>
            <p className="text-white/60 text-sm">
              Create and manage data disclosure requests
            </p>
          </div>
        </div>
      </div>

      {/* Error/Success Messages */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm flex-1">{error}</p>
          <Button
            onClick={() => setError(null)}
            variant="ghost"
            size="sm"
          >
            Dismiss
          </Button>
        </div>
      )}

      {successMessage && (
        <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg flex items-center gap-3">
          <Check className="w-5 h-5 text-green-400 flex-shrink-0" />
          <p className="text-green-400 text-sm flex-1">{successMessage}</p>
          <Button
            onClick={() => setSuccessMessage(null)}
            variant="ghost"
            size="sm"
          >
            Dismiss
          </Button>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card variant="glass" className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-yellow-500/20 flex items-center justify-center">
              <Clock className="w-4 h-4 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-white/95">{pendingRequests.length}</p>
              <p className="text-xs text-white/50">Pending</p>
            </div>
          </div>
        </Card>
        <Card variant="glass" className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-green-500/20 flex items-center justify-center">
              <Check className="w-4 h-4 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-white/95">{approvedRequests.length}</p>
              <p className="text-xs text-white/50">Approved</p>
            </div>
          </div>
        </Card>
        <Card variant="glass" className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
              <X className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-white/95">{rejectedRequests.length}</p>
              <p className="text-xs text-white/50">Rejected</p>
            </div>
          </div>
        </Card>
        <Card variant="glass" className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-orange-500/20 flex items-center justify-center">
              <X className="w-4 h-4 text-orange-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-white/95">{revokedRequests.length}</p>
              <p className="text-xs text-white/50">Revoked</p>
            </div>
          </div>
        </Card>
        <Card variant="glass" className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-white/10 flex items-center justify-center">
              <FileText className="w-4 h-4 text-white/40" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-white/95">{expiredRequests.length}</p>
              <p className="text-xs text-white/50">Expired</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabValue)}>
        <div className="flex items-center justify-between mb-4">
          <TabsList>
            <TabsTrigger value="requests" className="gap-2">
              <FileText className="w-4 h-4" />
              All Requests
            </TabsTrigger>
            <TabsTrigger value="create" className="gap-2">
              <Plus className="w-4 h-4" />
              Create Request
            </TabsTrigger>
          </TabsList>

          {activeTab === 'requests' && (
            <Button
              onClick={loadRequests}
              variant="outline"
              size="sm"
              disabled={isLoading}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          )}
        </div>

        {/* All Requests Tab */}
        <TabsContent value="requests" className="mt-0">
          {isLoading ? (
            <Card variant="glass">
              <CardContent className="py-12 text-center">
                <RefreshCw className="w-8 h-8 text-white/40 animate-spin mx-auto mb-3" />
                <p className="text-white/60">Loading disclosure requests...</p>
              </CardContent>
            </Card>
          ) : requests.length === 0 ? (
            <Card variant="glass">
              <CardContent className="py-12 text-center">
                <Shield className="w-12 h-12 text-white/20 mx-auto mb-3" />
                <p className="text-white/60">No disclosure requests yet</p>
                <p className="text-white/40 text-sm mt-1">
                  Create a new request to get started
                </p>
                <Button
                  onClick={() => setActiveTab('create')}
                  variant="glassPrimary"
                  className="mt-4"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Create Request
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Pending Requests */}
              {pendingRequests.length > 0 && (
                <div>
                  <h3 className="text-lg font-medium text-white/90 mb-3 flex items-center gap-2">
                    {getStatusIcon('pending')}
                    Pending Requests
                    <Badge variant="warning">{pendingRequests.length}</Badge>
                  </h3>
                  <div className="space-y-4">
                    {pendingRequests.map((request) => (
                      <DisclosureRequestCard
                        key={request.id}
                        request={request}
                        showActions={false}
                      />
                    ))}
                  </div>
                </div>
              )}

              {/* Approved Requests */}
              {approvedRequests.length > 0 && (
                <div>
                  <h3 className="text-lg font-medium text-white/90 mb-3 flex items-center gap-2">
                    {getStatusIcon('approved')}
                    Approved Requests
                    <Badge variant="success">{approvedRequests.length}</Badge>
                  </h3>
                  <div className="space-y-4">
                    {approvedRequests.map((request) => (
                      <DisclosureRequestCard
                        key={request.id}
                        request={request}
                        showActions={false}
                      />
                    ))}
                  </div>
                </div>
              )}

              {/* Other Requests (collapsed by default) */}
              {(rejectedRequests.length > 0 || revokedRequests.length > 0 || expiredRequests.length > 0) && (
                <Card variant="glass">
                  <CardHeader>
                    <CardTitle className="text-base">Other Requests</CardTitle>
                    <CardDescription>
                      Rejected, revoked, and expired requests
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {[...rejectedRequests, ...revokedRequests, ...expiredRequests].map((request) => (
                      <div
                        key={request.id}
                        className="p-4 bg-white/5 rounded-lg border border-white/10"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-white/90 font-medium">{request.requester_name}</p>
                            {request.requester_org && (
                              <p className="text-white/50 text-sm">{request.requester_org}</p>
                            )}
                            <p className="text-white/40 text-xs mt-1">{request.purpose}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant={STATUS_VARIANTS[request.status]}>
                              {STATUS_LABELS[request.status]}
                            </Badge>
                          </div>
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* Create Request Tab */}
        <TabsContent value="create" className="mt-0">
          <CreateDisclosureRequestForm
            onSubmit={handleCreateRequest}
            onCancel={() => setActiveTab('requests')}
            isLoading={isCreating}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default DisclosureAdminPage;
