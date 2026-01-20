import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { logsApi, AccessLog } from '@/api/client';

function getStatusColor(statusCode: number): string {
  if (statusCode >= 200 && statusCode < 300) {
    return 'bg-green-50 text-green-800';
  } else if (statusCode === 403) {
    return 'bg-orange-50 text-orange-800';
  } else if (statusCode >= 500) {
    return 'bg-red-50 text-red-800';
  }
  return 'bg-gray-50 text-gray-800';
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString();
}

export function RequestLog() {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchLogs = useCallback(async () => {
    try {
      const response = await logsApi.list(50);
      setLogs(response.data);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(fetchLogs, 2000);
    return () => clearInterval(interval);
  }, [isPaused, fetchLogs]);

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">Request Log</CardTitle>
          <Button
            variant={isPaused ? 'default' : 'outline'}
            size="sm"
            onClick={() => setIsPaused(!isPaused)}
          >
            {isPaused ? 'Resume' : 'Pause'}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading...</div>
        ) : logs.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No requests yet</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-gray-500">
                  <th className="pb-2 font-medium">Time</th>
                  <th className="pb-2 font-medium">Method</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Identity</th>
                  <th className="pb-2 font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr
                    key={log.id}
                    className={`border-b last:border-0 ${getStatusColor(log.status_code)}`}
                  >
                    <td className="py-2 font-mono text-xs">
                      {formatTime(log.created_at)}
                    </td>
                    <td className="py-2 font-mono">{log.method}</td>
                    <td className="py-2">{log.status_code}</td>
                    <td className="py-2 font-mono text-xs truncate max-w-[150px]">
                      {log.external_id}
                    </td>
                    <td className="py-2 font-mono text-xs">{log.ip_address}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
