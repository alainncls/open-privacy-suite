import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { testApi, TestRequestResult } from '@/api/client';
import { Send, Loader2, Zap, ShieldX, ShieldCheck, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { UserContextPanel } from './UserContextPanel';
import { ContractInfoPanel } from './ContractInfoPanel';

const RPC_METHODS = [
  { value: 'eth_blockNumber', label: 'eth_blockNumber' },
  { value: 'eth_chainId', label: 'eth_chainId' },
  { value: 'eth_getBalance', label: 'eth_getBalance' },
  { value: 'eth_call', label: 'eth_call' },
  { value: 'net_version', label: 'net_version' },
  { value: 'web3_clientVersion', label: 'web3_clientVersion' },
];

interface ERC20Method {
  value: string;
  label: string;
  selector: string;
  fields: { name: string; type: 'address' | 'uint256'; placeholder: string }[];
}

const ERC20_METHODS: ERC20Method[] = [
  {
    value: 'erc20_balanceOf',
    label: 'ERC20 - balanceOf',
    selector: '0x70a08231',
    fields: [
      { name: 'owner', type: 'address', placeholder: 'Owner address (0x...)' },
    ],
  },
  {
    value: 'erc20_totalSupply',
    label: 'ERC20 - totalSupply',
    selector: '0x18160ddd',
    fields: [],
  },
  {
    value: 'erc20_allowance',
    label: 'ERC20 - allowance',
    selector: '0xdd62ed3e',
    fields: [
      { name: 'owner', type: 'address', placeholder: 'Owner address (0x...)' },
      { name: 'spender', type: 'address', placeholder: 'Spender address (0x...)' },
    ],
  },
  {
    value: 'erc20_transfer',
    label: 'ERC20 - transfer',
    selector: '0xa9059cbb',
    fields: [
      { name: 'recipient', type: 'address', placeholder: 'Recipient address (0x...)' },
      { name: 'amount', type: 'uint256', placeholder: 'Amount (in wei)' },
    ],
  },
  {
    value: 'erc20_approve',
    label: 'ERC20 - approve',
    selector: '0x095ea7b3',
    fields: [
      { name: 'spender', type: 'address', placeholder: 'Spender address (0x...)' },
      { name: 'amount', type: 'uint256', placeholder: 'Amount (in wei)' },
    ],
  },
];

function encodeAddress(addr: string): string {
  const hex = addr.startsWith('0x') ? addr.slice(2) : addr;
  return hex.toLowerCase().padStart(64, '0');
}

function encodeUint256(value: string): string {
  const n = BigInt(value);
  return n.toString(16).padStart(64, '0');
}

function buildERC20Calldata(erc20Method: ERC20Method, fieldValues: Record<string, string>): string {
  let data = erc20Method.selector;
  for (const field of erc20Method.fields) {
    const val = fieldValues[field.name] || '';
    if (field.type === 'address') {
      data += encodeAddress(val);
    } else {
      data += encodeUint256(val);
    }
  }
  return data;
}

function isERC20(method: string): boolean {
  return method.startsWith('erc20_');
}

function getERC20Method(method: string): ERC20Method | undefined {
  return ERC20_METHODS.find((m) => m.value === method);
}

export function TestRequestPanel() {
  const [method, setMethod] = useState('eth_blockNumber');
  const [params, setParams] = useState('');
  const [jwtToken, setJwtToken] = useState('');
  const [contractAddress, setContractAddress] = useState('');
  const [erc20Fields, setErc20Fields] = useState<Record<string, string>>({});
  const [result, setResult] = useState<TestRequestResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const erc20Method = getERC20Method(method);
  const isErc20 = isERC20(method);

  const handleMethodChange = (value: string) => {
    setMethod(value);
    setErc20Fields({});
    setContractAddress('');
    setParams('');
    setResult(null);
    setError(null);
  };

  const handleSend = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let rpcMethod: string;
      let parsedParams: unknown[];

      if (isErc20 && erc20Method) {
        if (!contractAddress.trim()) {
          setError('Contract address is required');
          setLoading(false);
          return;
        }
        for (const field of erc20Method.fields) {
          if (!erc20Fields[field.name]?.trim()) {
            setError(`${field.name} is required`);
            setLoading(false);
            return;
          }
        }
        const calldata = buildERC20Calldata(erc20Method, erc20Fields);
        rpcMethod = 'eth_call';
        parsedParams = [{ to: contractAddress, data: calldata }, 'latest'];
      } else {
        rpcMethod = method;
        parsedParams = [];
        if (params.trim()) {
          parsedParams = JSON.parse(params);
          if (!Array.isArray(parsedParams)) {
            parsedParams = [parsedParams];
          }
        }
      }

      const response = await testApi.send(rpcMethod, parsedParams, jwtToken);
      setResult(response);
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
          <Select value={method} onValueChange={handleMethodChange}>
            <SelectTrigger className="w-[260px]">
              <SelectValue placeholder="Select method" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectLabel>RPC Methods</SelectLabel>
                {RPC_METHODS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectGroup>
              <SelectGroup>
                <SelectLabel>ERC20 Contract Calls</SelectLabel>
                {ERC20_METHODS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectGroup>
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

        {isErc20 && (
          <div className="space-y-3 animate-fade-in">
            <div>
              <label className="block text-sm font-medium text-[#374151] mb-2">
                Contract Address
              </label>
              <Input
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                placeholder="0x..."
              />
              <ContractInfoPanel contractAddress={contractAddress} />
            </div>
            {erc20Method?.fields.map((field) => (
              <div key={field.name}>
                <label className="block text-sm font-medium text-[#374151] mb-2">
                  {field.name.charAt(0).toUpperCase() + field.name.slice(1)}
                  {field.type === 'uint256' && (
                    <span className="text-xs text-[#6B7280] ml-1">(uint256)</span>
                  )}
                </label>
                <Input
                  value={erc20Fields[field.name] || ''}
                  onChange={(e) =>
                    setErc20Fields((prev) => ({ ...prev, [field.name]: e.target.value }))
                  }
                  placeholder={field.placeholder}
                />
              </div>
            ))}
          </div>
        )}

        {!isErc20 && (
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
        )}

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
            Advanced: Test with JWT Token
          </button>

          {showAdvanced && (
            <div className="mt-3 space-y-2 animate-fade-in">
              <label className="block text-sm font-medium text-[#374151] mb-2">
                JWT Token
              </label>
              <Textarea
                variant="code"
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                className="h-20"
              />
              <p className="text-xs text-[#6B7280]">
                Paste a JWT token to test as a specific user identity. Copy from the user dashboard after authentication.
              </p>
              <UserContextPanel jwtToken={jwtToken} />
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
              {result.status === 403 ? (
                <Badge variant="destructive" className="gap-1.5">
                  <ShieldX className="w-3 h-3" />
                  403 FORBIDDEN
                </Badge>
              ) : result.status === 200 ? (
                <Badge variant="success" className="gap-1.5">
                  <ShieldCheck className="w-3 h-3" />
                  200 OK
                </Badge>
              ) : (
                <Badge variant="warning" className="gap-1.5">
                  <AlertTriangle className="w-3 h-3" />
                  {result.status} ERROR
                </Badge>
              )}
              {result.data.latency_ms !== undefined && (
                <span className="text-sm text-[#6B7280]">
                  {result.data.latency_ms}ms
                </span>
              )}
              {result.data.identity && (
                <span className="text-xs text-[#6B7280] font-mono truncate max-w-[300px]" title={result.data.identity}>
                  Identity: {result.data.identity}
                </span>
              )}
            </div>
            {result.status === 200 && result.data.result !== undefined && (
              <div className="code-block">
                <pre className="whitespace-pre-wrap break-all">
                  {JSON.stringify(result.data.result, null, 2)}
                </pre>
              </div>
            )}
            {result.data.error && (
              <div className="p-4 rounded-lg bg-[#FEF9C3] border border-[#FDE047]">
                <span className="text-[#854D0E] text-sm">{result.data.error}</span>
                {result.status === 403 && !jwtToken.trim() && (
                  <p className="text-[#92400E] text-xs mt-2">
                    No JWT token provided. Expand "Advanced: Test with JWT Token" below the Send button and paste a valid token to test as a specific user.
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
