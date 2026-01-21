import { useState, useEffect, useCallback } from 'react';
import { StatusCard } from './StatusCard';
import { RequestLog } from './RequestLog';
import { TestRequestPanel } from './TestRequestPanel';
import { statusApi, StatusResponse } from '@/api/client';
import { Loader2 } from 'lucide-react';

export function Dashboard() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const response = await statusApi.get();
      setStatus(response.data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16" role="status" aria-live="polite">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-primary-400 animate-spin" aria-hidden="true" />
          <p className="text-white/70">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="glass-card p-6 animate-fade-in">
        <div className="flex items-center gap-3 text-red-400">
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span>Failed to load status: {error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
        <div className="animate-fade-in-up h-full" style={{ animationDelay: '0ms' }}>
          <StatusCard
            title="Proxy"
            status={status?.proxy.status || 'unknown'}
            port={status?.proxy.port}
          />
        </div>
        <div className="animate-fade-in-up h-full" style={{ animationDelay: '100ms' }}>
          <StatusCard
            title="Node"
            status={status?.node.status || 'unknown'}
            url={status?.node.url}
            latency={status?.node.latency_ms}
            error={status?.node.error}
          />
        </div>
      </div>

      {/* Test Request Panel */}
      <div className="animate-fade-in-up" style={{ animationDelay: '200ms' }}>
        <TestRequestPanel />
      </div>

      {/* Request Log */}
      <div className="animate-fade-in-up" style={{ animationDelay: '300ms' }}>
        <RequestLog />
      </div>
    </div>
  );
}
