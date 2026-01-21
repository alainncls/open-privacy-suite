import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { testApi, TestRequestResponse } from '@/api/client';
import { Send, Loader2, Zap, ShieldX, ShieldCheck, AlertTriangle } from 'lucide-react';

const COMMON_METHODS = [
  { value: 'eth_blockNumber', label: 'eth_blockNumber' },
  { value: 'eth_chainId', label: 'eth_chainId' },
  { value: 'eth_getBalance', label: 'eth_getBalance' },
  { value: 'eth_call', label: 'eth_call' },
  { value: 'net_version', label: 'net_version' },
  { value: 'web3_clientVersion', label: 'web3_clientVersion' },
];

export function TestRequestPanel() {
  const [method, setMethod] = useState('eth_blockNumber');
  const [params, setParams] = useState('');
  const [result, setResult] = useState<TestRequestResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSend = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let parsedParams: unknown[] = [];
      if (params.trim()) {
        parsedParams = JSON.parse(params);
        if (!Array.isArray(parsedParams)) {
          parsedParams = [parsedParams];
        }
      }

      const response = await testApi.send(method, parsedParams);
      setResult(response.data);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError('Invalid JSON in params');
      } else {
        setError(err instanceof Error ? err.message : 'Request failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center">
            <Zap className="w-5 h-5 text-yellow-400" />
          </div>
          <CardTitle className="text-lg">Test Request</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-3">
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger className="w-[220px]">
              <SelectValue placeholder="Select method" />
            </SelectTrigger>
            <SelectContent>
              {COMMON_METHODS.map((m) => (
                <SelectItem key={m.value} value={m.value}>
                  {m.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button onClick={handleSend} disabled={loading} className="gap-2">
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Sending...
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                Send
              </>
            )}
          </Button>
        </div>

        <div>
          <label className="block text-sm font-medium text-white/70 mb-2">
            Params (JSON array, optional)
          </label>
          <Textarea
            variant="code"
            value={params}
            onChange={(e) => setParams(e.target.value)}
            placeholder='["0x...", "latest"]'
            className="h-20"
          />
        </div>

        {error && (
          <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <span className="text-red-400 text-sm">{error}</span>
          </div>
        )}

        {result && (
          <div className="space-y-3 animate-fade-in">
            <div className="flex items-center gap-3">
              {result.blocked ? (
                <Badge variant="destructive" className="gap-1.5">
                  <ShieldX className="w-3 h-3" />
                  BLOCKED
                </Badge>
              ) : result.success ? (
                <Badge variant="success" className="gap-1.5">
                  <ShieldCheck className="w-3 h-3" />
                  ALLOWED
                </Badge>
              ) : (
                <Badge variant="warning" className="gap-1.5">
                  <AlertTriangle className="w-3 h-3" />
                  ERROR
                </Badge>
              )}
              <span className="text-sm text-white/50">
                {result.latency_ms}ms
              </span>
            </div>
            {result.success && result.result !== undefined && (
              <div className="glass-code">
                <pre className="whitespace-pre-wrap break-all">
                  {JSON.stringify(result.result, null, 2)}
                </pre>
              </div>
            )}
            {result.error && (
              <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/20">
                <span className="text-orange-400 text-sm">{result.error}</span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
