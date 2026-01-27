import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, FileText, Key, RefreshCw, Check, AlertCircle, ArrowLeft } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useAuth } from '@/contexts/AuthContext';
import { disclosureApi } from '@/api/disclosure';
import { DisclosureRequestCard, DisclosureGrantCard } from '@/components/disclosure';
import type { DisclosureRequest, DisclosureGrant } from '@/types/disclosure';

export function DisclosurePage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, isLoading: isAuthLoading } = useAuth();

  const [pendingRequests, setPendingRequests] = useState<DisclosureRequest[]>([]);
  const [activeGrants, setActiveGrants] = useState<DisclosureGrant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Success dialog state
  const [showSuccessDialog, setShowSuccessDialog] = useState(false);

  // Redirect if not authenticated (wait for auth to load first)
  useEffect(() => {
    console.log('[DisclosurePage] Auth check:', { isAuthLoading, isAuthenticated, accessToken: !!accessToken });
    if (!isAuthLoading && !isAuthenticated) {
      console.log('[DisclosurePage] Redirecting to /login because not authenticated');
      navigate('/login');
    }
  }, [isAuthenticated, isAuthLoading, navigate, accessToken]);

  const loadData = useCallback(async () => {
    if (!accessToken) return;

    setIsLoading(true);
    setError(null);

    try {
      const [requestsResponse, grantsResponse] = await Promise.all([
        disclosureApi.user.getMyRequests(accessToken),
        disclosureApi.user.getMyGrants(accessToken),
      ]);

      // Filter to only show pending requests
      setPendingRequests(
        requestsResponse.data.filter((r) => r.status === 'pending')
      );
      setActiveGrants(grantsResponse.data);
    } catch (err) {
      console.error('Failed to load disclosure data:', err);
      setError('Failed to load disclosure data. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, [accessToken]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleApprove = async (requestId: string) => {
    if (!accessToken) return;

    try {
      await disclosureApi.user.approveRequest(accessToken, requestId);
      setShowSuccessDialog(true);
      // Reload data to reflect changes
      await loadData();
    } catch (err) {
      console.error('Failed to approve request:', err);
      setError('Failed to approve request. Please try again.');
    }
  };

  const handleReject = async (requestId: string, reason?: string) => {
    if (!accessToken) return;

    try {
      await disclosureApi.user.rejectRequest(accessToken, requestId, reason ? { reason } : undefined);
      // Reload data to reflect changes
      await loadData();
    } catch (err) {
      console.error('Failed to reject request:', err);
      setError('Failed to reject request. Please try again.');
    }
  };

  const handleRevoke = async (requestId: string, reason?: string) => {
    if (!accessToken) return;

    try {
      await disclosureApi.user.revokeRequest(accessToken, requestId, reason ? { reason } : undefined);
      // Reload data to reflect changes
      await loadData();
    } catch (err) {
      console.error('Failed to revoke grant:', err);
      setError('Failed to revoke grant. Please try again.');
    }
  };


  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen bg-[#F1F5F9] p-4">
      <div className="max-w-2xl mx-auto animate-fade-in">
        {/* Header */}
        <div className="mb-8">
          <Button
            onClick={() => navigate('/success')}
            variant="ghost"
            size="sm"
            className="mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Button>

          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#8950FA] to-[#A478FC] flex items-center justify-center shadow-lg shadow-primary">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-[#0F0F0F]">Data Disclosure</h1>
              <p className="text-[#6B7280]">Manage access to your data</p>
            </div>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <Card variant="default" className="mb-4 border-[#FEE2E2]">
            <CardContent className="py-4">
              <div className="flex items-center gap-3">
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
            </CardContent>
          </Card>
        )}

        {/* Info Card */}
        <Card variant="default" className="mb-6">
          <CardContent className="py-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#F5F3FF] flex items-center justify-center flex-shrink-0">
                <FileText className="w-5 h-5 text-[#8950FA]" />
              </div>
              <div>
                <h3 className="text-[#0F0F0F] font-medium">Selective Disclosure</h3>
                <p className="text-[#6B7280] text-sm mt-1">
                  Review and manage requests from auditors, regulators, and other parties
                  who need access to your activity data. You control what data is shared
                  and can revoke access at any time.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Pending Requests Section */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-[#0F0F0F]">Pending Requests</h2>
              {pendingRequests.length > 0 && (
                <Badge variant="warning">{pendingRequests.length}</Badge>
              )}
            </div>
            <Button
              onClick={loadData}
              variant="ghost"
              size="sm"
              disabled={isLoading}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          {isLoading ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <RefreshCw className="w-8 h-8 text-[#94A3B8] animate-spin mx-auto mb-3" />
                <p className="text-[#6B7280]">Loading requests...</p>
              </CardContent>
            </Card>
          ) : pendingRequests.length === 0 ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <Shield className="w-12 h-12 text-[#CBD5E1] mx-auto mb-3" />
                <p className="text-[#6B7280]">No pending disclosure requests</p>
                <p className="text-[#94A3B8] text-sm mt-1">
                  You will be notified when someone requests access to your data
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {pendingRequests.map((request) => (
                <DisclosureRequestCard
                  key={request.id}
                  request={request}
                  onApprove={handleApprove}
                  onReject={handleReject}
                  isLoading={isLoading}
                />
              ))}
            </div>
          )}
        </div>

        {/* Active Grants Section */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <h2 className="text-lg font-semibold text-[#0F0F0F]">Active Data Access Grants</h2>
            {activeGrants.filter((g) => !g.revoked_at && new Date(g.valid_until) > new Date()).length > 0 && (
              <Badge variant="success">
                {activeGrants.filter((g) => !g.revoked_at && new Date(g.valid_until) > new Date()).length}
              </Badge>
            )}
          </div>

          {isLoading ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <RefreshCw className="w-8 h-8 text-[#94A3B8] animate-spin mx-auto mb-3" />
                <p className="text-[#6B7280]">Loading grants...</p>
              </CardContent>
            </Card>
          ) : activeGrants.length === 0 ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <Key className="w-12 h-12 text-[#CBD5E1] mx-auto mb-3" />
                <p className="text-[#6B7280]">No active data access grants</p>
                <p className="text-[#94A3B8] text-sm mt-1">
                  Grants you approve will appear here
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {activeGrants.map((grant) => (
                <DisclosureGrantCard
                  key={grant.id}
                  grant={grant}
                  onRevoke={handleRevoke}
                  isLoading={isLoading}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Success Dialog */}
      <Dialog open={showSuccessDialog} onOpenChange={setShowSuccessDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Check className="w-5 h-5 text-[#166534]" />
              Access Granted Successfully
            </DialogTitle>
          </DialogHeader>

          <div className="py-4">
            <div className="p-4 bg-[#DCFCE7] border border-[#BBF7D0] rounded-lg">
              <p className="text-sm text-[#166534]">
                The disclosure request has been approved. The authorized auditor can now
                access your data through their authenticated session.
              </p>
            </div>
          </div>

          <div className="flex justify-end">
            <Button onClick={() => setShowSuccessDialog(false)}>
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default DisclosurePage;
