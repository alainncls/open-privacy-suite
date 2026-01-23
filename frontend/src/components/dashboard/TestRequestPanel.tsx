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
import { Send, Loader2, Zap, ShieldX, ShieldCheck, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';

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
  const [jwzToken, setJwzToken] = useState('');
  const [result, setResult] = useState<TestRequestResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

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

      const response = await testApi.send(method, parsedParams, jwzToken);
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
          <div className="w-10 h-10 rounded-lg bg-[#FEF9C3] flex items-center justify-center">
            <Zap className="w-5 h-5 text-[#854D0E]" />
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
          <label className="block text-sm font-medium text-[#374151] mb-2">
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

        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-sm text-[#6B7280] hover:text-[#374151] transition-colors"
          >
            {showAdvanced ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
            Advanced: Test with JWZ Token
          </button>
          
          {showAdvanced && (
            <div className="mt-3 space-y-2 animate-fade-in">
              <label className="block text-sm font-medium text-[#374151] mb-2">
                JWZ Token
              </label>
              <Textarea
                variant="code"
                value={jwzToken}
                onChange={(e) => setJwzToken(e.target.value)}
                placeholder="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
                className="h-20"
              />
              <p className="text-xs text-[#6B7280]">
                JWZ token for testing ZK-attested identities. This token contains zero-knowledge proof credentials.
              </p>
            </div>
          )}
        </div>

        {error && (
          <div className="p-4 rounded-lg bg-[#FEE2E2] border border-[#FECACA] flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
            <span className="text-[#991B1B] text-sm">{error}</span>
          </div>
        )}

        {result && (
          <div className="space-y-3 animate-fade-in">
            <div className="flex items-center gap-3 flex-wrap">
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
              <span className="text-sm text-[#6B7280]">
                {result.latency_ms}ms
              </span>
              {result.identity && (
                <span className="text-xs text-[#6B7280] font-mono truncate max-w-[300px]" title={result.identity}>
                  Identity: {result.identity}
                </span>
              )}
            </div>
            {result.success && result.result !== undefined && (
              <div className="code-block">
                <pre className="whitespace-pre-wrap break-all">
                  {JSON.stringify(result.result, null, 2)}
                </pre>
              </div>
            )}
            {result.error && (
              <div className="p-4 rounded-lg bg-[#FEF9C3] border border-[#FDE047]">
                <span className="text-[#854D0E] text-sm">{result.error}</span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
