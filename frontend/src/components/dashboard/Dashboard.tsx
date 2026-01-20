import { useState, useEffect, useCallback } from 'react';
import { StatusCard } from './StatusCard';
import { RequestLog } from './RequestLog';
import { TestRequestPanel } from './TestRequestPanel';
import { statusApi, StatusResponse } from '@/api/client';

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
      <div className="text-center py-8 text-gray-500">
        Loading dashboard...
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="p-4 bg-red-50 rounded-md text-red-700">
        Failed to load status: {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <StatusCard
          title="Proxy"
          status={status?.proxy.status || 'unknown'}
          port={status?.proxy.port}
        />
        <StatusCard
          title="Node"
          status={status?.node.status || 'unknown'}
          url={status?.node.url}
          latency={status?.node.latency_ms}
          error={status?.node.error}
        />
      </div>

      {/* Test Request Panel */}
      <TestRequestPanel />

      {/* Request Log */}
      <RequestLog />
    </div>
  );
}
