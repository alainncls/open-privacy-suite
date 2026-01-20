import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { testApi, TestRequestResponse } from '@/api/client';

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
      <CardHeader className="pb-2">
        <CardTitle className="text-lg">Test Request</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger className="w-[200px]">
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
          <Button onClick={handleSend} disabled={loading}>
            {loading ? 'Sending...' : 'Send'}
          </Button>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Params (JSON array, optional)
          </label>
          <textarea
            value={params}
            onChange={(e) => setParams(e.target.value)}
            placeholder='["0x...", "latest"]'
            className="w-full h-20 p-2 border border-gray-200 rounded-md font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-gray-950"
          />
        </div>

        {error && (
          <div className="p-3 bg-red-50 rounded-md text-red-700 text-sm">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Badge variant={result.blocked ? 'destructive' : result.success ? 'success' : 'warning'}>
                {result.blocked ? 'BLOCKED' : result.success ? 'ALLOWED' : 'ERROR'}
              </Badge>
              <span className="text-sm text-gray-500">
                {result.latency_ms}ms
              </span>
            </div>
            {result.success && result.result !== undefined && (
              <pre className="p-3 bg-gray-50 rounded-md text-sm font-mono overflow-x-auto">
                {JSON.stringify(result.result, null, 2)}
              </pre>
            )}
            {result.error && (
              <div className="p-3 bg-orange-50 rounded-md text-orange-700 text-sm">
                {result.error}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
