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
          <div className="w-10 h-10 rounded-lg bg-[#F5F3FF] flex items-center justify-center">
            <Shield className="w-5 h-5 text-[#8950FA]" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-[#0F0F0F]">Disclosure Management</h1>
            <p className="text-[#6B7280] text-sm">
              Create and manage data disclosure requests
            </p>
          </div>
        </div>
      </div>

      {/* Error/Success Messages */}
      {error && (
        <div className="p-4 bg-[#FEE2E2] border border-[#FECACA] rounded-lg flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0" />
          <p className="text-[#991B1B] text-sm flex-1">{error}</p>
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
        <div className="p-4 bg-[#DCFCE7] border border-[#BBF7D0] rounded-lg flex items-center gap-3">
          <Check className="w-5 h-5 text-[#166534] flex-shrink-0" />
          <p className="text-[#166534] text-sm flex-1">{successMessage}</p>
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
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#FEF9C3] flex items-center justify-center">
              <Clock className="w-4 h-4 text-[#854D0E]" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-[#0F0F0F]">{pendingRequests.length}</p>
              <p className="text-xs text-[#6B7280]">Pending</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#DCFCE7] flex items-center justify-center">
              <Check className="w-4 h-4 text-[#166534]" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-[#0F0F0F]">{approvedRequests.length}</p>
              <p className="text-xs text-[#6B7280]">Approved</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#FEE2E2] flex items-center justify-center">
              <X className="w-4 h-4 text-[#991B1B]" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-[#0F0F0F]">{rejectedRequests.length}</p>
              <p className="text-xs text-[#6B7280]">Rejected</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#FFEDD5] flex items-center justify-center">
              <X className="w-4 h-4 text-[#9A3412]" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-[#0F0F0F]">{revokedRequests.length}</p>
              <p className="text-xs text-[#6B7280]">Revoked</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#F1F5F9] flex items-center justify-center">
              <FileText className="w-4 h-4 text-[#94A3B8]" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-[#0F0F0F]">{expiredRequests.length}</p>
              <p className="text-xs text-[#6B7280]">Expired</p>
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
            <Card>
              <CardContent className="py-12 text-center">
                <RefreshCw className="w-8 h-8 text-[#94A3B8] animate-spin mx-auto mb-3" />
                <p className="text-[#6B7280]">Loading disclosure requests...</p>
              </CardContent>
            </Card>
          ) : requests.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F5F3FF] flex items-center justify-center">
                  <Shield className="w-8 h-8 text-[#94A3B8]" />
                </div>
                <p className="text-[#6B7280]">No disclosure requests yet</p>
                <p className="text-[#94A3B8] text-sm mt-1">
                  Create a new request to get started
                </p>
                <Button
                  onClick={() => setActiveTab('create')}
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
                  <h3 className="text-lg font-medium text-[#0F0F0F] mb-3 flex items-center gap-2">
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
                  <h3 className="text-lg font-medium text-[#0F0F0F] mb-3 flex items-center gap-2">
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
                <Card>
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
                        className="p-4 bg-[#F1F5F9] rounded-lg border border-[#E2E8F0]"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-[#0F0F0F] font-medium">{request.requester_name}</p>
                            {request.requester_org && (
                              <p className="text-[#6B7280] text-sm">{request.requester_org}</p>
                            )}
                            <p className="text-[#94A3B8] text-xs mt-1">{request.purpose}</p>
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
