import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { FlaskConical, Loader2, Copy, CheckCircle2, Rocket } from 'lucide-react';
import { devApi, DeployDemoERC20Response } from '@/api/client';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';

const isDev = import.meta.env.DEV;

export function DeployDemoTokenPanel() {
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState<string>('__none__');
  const [name, setName] = useState('DemoERC20');
  const [deploying, setDeploying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deployments, setDeployments] = useState<DeployDemoERC20Response[]>([]);
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);

  useEffect(() => {
    if (!isDev) return;
    rbacApi.orgs
      .list({ limit: 1000 })
      .then((res) => setOrgs(res.data.data || []))
      .catch(() => {});
  }, []);

  if (!isDev) return null;

  const handleDeploy = async () => {
    setDeploying(true);
    setError(null);
    try {
      const res = await devApi.deployDemoERC20({
        org_id: selectedOrgId === '__none__' ? undefined : selectedOrgId,
        name: name || undefined,
      });
      setDeployments((prev) => [res.data, ...prev]);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: string } } };
        setError(axiosErr.response?.data?.error || 'Deployment failed');
      } else {
        setError(err instanceof Error ? err.message : 'Deployment failed');
      }
    } finally {
      setDeploying(false);
    }
  };

  const handleCopy = (address: string) => {
    navigator.clipboard.writeText(address);
    setCopiedAddress(address);
    setTimeout(() => setCopiedAddress(null), 2000);
  };

  return (
    <Card className="border-dashed border-[#FDE047]">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#FEF9C3] flex items-center justify-center">
              <FlaskConical className="w-5 h-5 text-[#854D0E]" />
            </div>
            <div>
              <CardTitle className="text-lg">Dev Tools</CardTitle>
              <p className="text-sm text-[#6B7280] mt-0.5">Deploy demo contracts for testing</p>
            </div>
          </div>
          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-[#FEF9C3] text-[#854D0E] text-xs font-medium">
            <FlaskConical className="w-3 h-3" />
            Development Only
          </span>
        </div>
      </CardHeader>
      <CardContent>
        {/* Deploy form */}
        <div className="flex items-end gap-3">
          <div className="flex-1 min-w-[180px]">
            <label className="text-xs font-medium text-[#6B7280] mb-1.5 block">
              Organization (optional)
            </label>
            <Select value={selectedOrgId} onValueChange={setSelectedOrgId}>
              <SelectTrigger>
                <SelectValue placeholder="No org (unregistered)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">No org (unregistered)</SelectItem>
                {orgs.map((org) => (
                  <SelectItem key={org.id} value={org.id}>
                    {org.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="w-[200px]">
            <label className="text-xs font-medium text-[#6B7280] mb-1.5 block">
              Token Name
            </label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="DemoERC20"
            />
          </div>

          <Button onClick={handleDeploy} disabled={deploying}>
            {deploying ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Deploying...
              </>
            ) : (
              <>
                <Rocket className="w-4 h-4 mr-2" />
                Deploy DemoERC20
              </>
            )}
          </Button>
        </div>

        {/* Error */}
        {error && (
          <div className="mt-3 p-3 rounded-lg bg-[#FEF2F2] text-[#991B1B] text-sm">
            {error}
          </div>
        )}

        {/* Deployment history */}
        {deployments.length > 0 && (
          <div className="mt-4 space-y-2">
            <p className="text-xs font-medium text-[#6B7280]">Deployed this session</p>
            {deployments.map((d, i) => (
              <div
                key={`${d.address}-${i}`}
                className="flex items-center gap-3 p-2.5 rounded-lg bg-[#F9FAFB] border border-[#E5E7EB]"
              >
                <span className="text-sm font-medium text-[#111827]">{d.name}</span>
                <code
                  className="text-xs font-mono text-[#6B7280] truncate max-w-[200px]"
                  title={d.address}
                >
                  {d.address}
                </code>
                <button
                  onClick={() => handleCopy(d.address)}
                  className="p-1 rounded hover:bg-[#E5E7EB] transition-colors flex-shrink-0"
                  title="Copy address"
                >
                  {copiedAddress === d.address ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#16A34A]" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-[#9CA3AF]" />
                  )}
                </button>
                {copiedAddress === d.address && (
                  <span className="text-xs text-[#16A34A]">Copied!</span>
                )}
                {d.registered && (
                  <span className="ml-auto inline-flex items-center px-2 py-0.5 rounded-full bg-[#DBEAFE] text-[#1E40AF] text-xs font-medium">
                    Registered
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
