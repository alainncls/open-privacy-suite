import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Server, Activity, Wifi, WifiOff, AlertCircle } from 'lucide-react';

interface StatusCardProps {
  title: string;
  status: string;
  port?: string;
  url?: string;
  latency?: number;
  error?: string;
}

function getStatusConfig(status: string): {
  dotClass: string;
  icon: React.ReactNode;
  label: string;
} {
  switch (status.toLowerCase()) {
    case 'running':
    case 'connected':
      return {
        dotClass: 'status-dot-success',
        icon: <Wifi className="w-4 h-4" />,
        label: status,
      };
    case 'error':
      return {
        dotClass: 'status-dot-error',
        icon: <AlertCircle className="w-4 h-4" />,
        label: status,
      };
    case 'disconnected':
      return {
        dotClass: 'status-dot-warning',
        icon: <WifiOff className="w-4 h-4" />,
        label: status,
      };
    default:
      return {
        dotClass: 'status-dot-warning',
        icon: <Activity className="w-4 h-4" />,
        label: status,
      };
  }
}

function getLatencyColor(latency: number): string {
  if (latency < 100) return 'text-green-400';
  if (latency < 300) return 'text-yellow-400';
  return 'text-red-400';
}

export function StatusCard({ title, status, port, url, latency, error }: StatusCardProps) {
  const statusConfig = getStatusConfig(status);
  const isProxy = title === 'Proxy';

  return (
    <Card variant="elevated" className="group h-full flex flex-col">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
              {isProxy ? (
                <Server className="w-5 h-5 text-primary-400" />
              ) : (
                <Activity className="w-5 h-5 text-accent-400" />
              )}
            </div>
            <CardTitle className="text-lg">{title}</CardTitle>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5" role="status">
            <div className={statusConfig.dotClass} aria-hidden="true" />
            <span className="text-sm text-white/90 capitalize">{statusConfig.label}</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1">
        <div className="space-y-2">
          {port && (
            <div className="flex justify-between items-center p-2.5 rounded-lg bg-white/5">
              <span className="text-white/70 text-sm">Port</span>
              <span className="font-mono text-sm text-white/90">{port}</span>
            </div>
          )}
          {url && (
            <div className="flex justify-between items-center p-2.5 rounded-lg bg-white/5">
              <span className="text-white/70 text-sm">URL</span>
              <span className="font-mono text-xs text-white/90 truncate max-w-[200px]">{url}</span>
            </div>
          )}
          {latency !== undefined && (
            <div className="flex justify-between items-center p-2.5 rounded-lg bg-white/5">
              <span className="text-white/70 text-sm">Latency</span>
              <span className={`font-mono text-sm ${getLatencyColor(latency)}`}>
                {latency}ms
                <span className="sr-only">
                  {latency < 100 ? ' (good)' : latency < 300 ? ' (moderate)' : ' (slow)'}
                </span>
              </span>
            </div>
          )}
          {error && (
            <div className="mt-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
              <div className="flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                <span className="text-red-400 text-sm">{error}</span>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
