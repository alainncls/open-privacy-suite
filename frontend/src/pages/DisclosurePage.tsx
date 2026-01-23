import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, FileText, Key, RefreshCw, Check, AlertCircle } from 'lucide-react'; // Key still used for grants section
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
  const { isAuthenticated, accessToken } = useAuth();

  const [pendingRequests, setPendingRequests] = useState<DisclosureRequest[]>([]);
  const [activeGrants, setActiveGrants] = useState<DisclosureGrant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Success dialog state
  const [showSuccessDialog, setShowSuccessDialog] = useState(false);

  // Redirect if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

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
    <div className="min-h-screen bg-mesh">
      {/* Header */}
      <header className="glass-nav sticky top-0 z-40">
        <div className="max-w-4xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shadow-lg shadow-primary-500/30">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-white/95">Data Disclosure</h1>
                <p className="text-xs text-white/60">Manage access to your data</p>
              </div>
            </div>
            <Button
              onClick={() => navigate('/success')}
              variant="outline"
              size="sm"
            >
              Back to Dashboard
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-6 py-8">
        <div className="animate-fade-in space-y-8">
          {/* Error Alert */}
          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <p className="text-red-400 text-sm">{error}</p>
              <Button
                onClick={() => setError(null)}
                variant="ghost"
                size="sm"
                className="ml-auto"
              >
                Dismiss
              </Button>
            </div>
          )}

          {/* Info Card */}
          <Card variant="glass">
            <CardContent className="py-4">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary-500/20 flex items-center justify-center flex-shrink-0">
                  <FileText className="w-5 h-5 text-primary-400" />
                </div>
                <div>
                  <h3 className="text-white/90 font-medium">Selective Disclosure</h3>
                  <p className="text-white/60 text-sm mt-1">
                    Review and manage requests from auditors, regulators, and other parties
                    who need access to your activity data. You control what data is shared
                    and can revoke access at any time.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Pending Requests Section */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-semibold text-white/95">Pending Requests</h2>
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
              <Card variant="glass">
                <CardContent className="py-12 text-center">
                  <RefreshCw className="w-8 h-8 text-white/40 animate-spin mx-auto mb-3" />
                  <p className="text-white/60">Loading requests...</p>
                </CardContent>
              </Card>
            ) : pendingRequests.length === 0 ? (
              <Card variant="glass">
                <CardContent className="py-12 text-center">
                  <Shield className="w-12 h-12 text-white/20 mx-auto mb-3" />
                  <p className="text-white/60">No pending disclosure requests</p>
                  <p className="text-white/40 text-sm mt-1">
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
          </section>

          {/* Active Grants Section */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <h2 className="text-xl font-semibold text-white/95">Active Data Access Grants</h2>
              {activeGrants.filter((g) => !g.revoked_at && new Date(g.valid_until) > new Date()).length > 0 && (
                <Badge variant="success">
                  {activeGrants.filter((g) => !g.revoked_at && new Date(g.valid_until) > new Date()).length}
                </Badge>
              )}
            </div>

            {isLoading ? (
              <Card variant="glass">
                <CardContent className="py-12 text-center">
                  <RefreshCw className="w-8 h-8 text-white/40 animate-spin mx-auto mb-3" />
                  <p className="text-white/60">Loading grants...</p>
                </CardContent>
              </Card>
            ) : activeGrants.length === 0 ? (
              <Card variant="glass">
                <CardContent className="py-12 text-center">
                  <Key className="w-12 h-12 text-white/20 mx-auto mb-3" />
                  <p className="text-white/60">No active data access grants</p>
                  <p className="text-white/40 text-sm mt-1">
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
          </section>
        </div>
      </main>

      {/* Success Dialog */}
      <Dialog open={showSuccessDialog} onOpenChange={setShowSuccessDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Check className="w-5 h-5 text-green-400" />
              Access Granted Successfully
            </DialogTitle>
          </DialogHeader>

          <div className="py-4">
            <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
              <p className="text-sm text-white/80">
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
