import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface StatusCardProps {
  title: string;
  status: string;
  port?: string;
  url?: string;
  latency?: number;
  error?: string;
}

function getStatusVariant(status: string): 'success' | 'destructive' | 'warning' {
  switch (status.toLowerCase()) {
    case 'running':
    case 'connected':
      return 'success';
    case 'error':
      return 'destructive';
    case 'disconnected':
      return 'warning';
    default:
      return 'warning';
  }
}

export function StatusCard({ title, status, port, url, latency, error }: StatusCardProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">{title}</CardTitle>
          <Badge variant={getStatusVariant(status)}>{status}</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-1 text-sm text-gray-600">
          {port && (
            <div className="flex justify-between">
              <span>Port:</span>
              <span className="font-mono">{port}</span>
            </div>
          )}
          {url && (
            <div className="flex justify-between">
              <span>URL:</span>
              <span className="font-mono text-xs truncate max-w-[200px]">{url}</span>
            </div>
          )}
          {latency !== undefined && (
            <div className="flex justify-between">
              <span>Latency:</span>
              <span className="font-mono">{latency}ms</span>
            </div>
          )}
          {error && (
            <div className="mt-2 p-2 bg-red-50 rounded text-red-700 text-xs">
              {error}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
