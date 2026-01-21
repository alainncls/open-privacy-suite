import { useEffect, useState } from 'react';
import { logsApi, AccessLog } from '../api/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ScrollText, RefreshCw, Loader2, Clock } from 'lucide-react';

function AccessLogs() {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadLogs();
    const interval = setInterval(loadLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadLogs = async () => {
    try {
      const response = await logsApi.list(100);
      setLogs(response.data || []);
    } catch (error: unknown) {
      console.error('Failed to load logs:', error);
      setLogs([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    loadLogs();
  };

  const getStatusBadgeVariant = (statusCode: number): 'success' | 'warning' | 'destructive' | 'default' => {
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 400 && statusCode < 500) return 'warning';
    return 'destructive';
  };

  const formatDateTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return {
      date: date.toLocaleDateString(),
      time: date.toLocaleTimeString(),
    };
  };

  return (
    <Card className="animate-fade-in">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center">
              <ScrollText className="w-5 h-5 text-accent-400" />
            </div>
            <div>
              <CardTitle className="text-lg">Access Logs</CardTitle>
              <div className="flex items-center gap-2 mt-1" role="status" aria-live="polite">
                <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" aria-hidden="true" />
                <span className="text-xs text-white/60">Auto-refreshing every 5s</span>
              </div>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing}
            className="gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading && logs.length === 0 ? (
          <div className="flex items-center justify-center py-12" role="status" aria-live="polite">
            <Loader2 className="w-6 h-6 text-white/50 animate-spin" aria-hidden="true" />
            <span className="sr-only">Loading access logs...</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
              <Clock className="w-8 h-8 text-white/30" />
            </div>
            <p className="text-white/50">No access logs yet</p>
            <p className="text-white/30 text-sm mt-1">Logs will appear here when requests are made</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>External ID</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>IP Address</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map((log, index) => {
                const { date, time } = formatDateTime(log.created_at);
                return (
                  <TableRow
                    key={log.id}
                    className="animate-fade-in"
                    style={{ animationDelay: `${index * 15}ms` }}
                  >
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-mono text-xs text-white/80">{time}</span>
                        <span className="font-mono text-xs text-white/40">{date}</span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-sm text-white/80">
                      {log.external_id}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">
                        {log.method}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={getStatusBadgeVariant(log.status_code)}>
                        {log.status_code}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-white/60">
                      {log.ip_address || '-'}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export default AccessLogs;
