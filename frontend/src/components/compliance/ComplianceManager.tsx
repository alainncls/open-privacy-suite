import { useState, useEffect, createContext, useContext } from 'react';
import { Outlet, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import {
  Scale,
  Settings,
  Coins,
  FileText,
  ShieldBan,
  ScrollText,
  Building2,
  Globe,
  Loader2,
} from 'lucide-react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';

type ComplianceTab = 'config' | 'tokens' | 'travel-rules' | 'sanctions' | 'logs';

interface ComplianceOrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
}

export const ComplianceOrgContext = createContext<ComplianceOrgContextType | null>(null);

export function useComplianceOrgContext() {
  const context = useContext(ComplianceOrgContext);
  if (!context) {
    throw new Error('useComplianceOrgContext must be used within ComplianceManager');
  }
  return context;
}

export default function ComplianceManager() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);

  const getActiveTab = (): ComplianceTab => {
    const path = location.pathname;
    if (path.includes('/tokens')) return 'tokens';
    if (path.includes('/travel-rules')) return 'travel-rules';
    if (path.includes('/sanctions')) return 'sanctions';
    if (path.includes('/logs')) return 'logs';
    return 'config';
  };

  const activeTab = getActiveTab();

  const loadOrganizations = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list({ limit: 1000 });
      const orgs = response.data?.data || [];
      setOrganizations(orgs);

      const orgIdFromUrl = searchParams.get('org');
      if (orgIdFromUrl) {
        const orgFromUrl = orgs.find((o: Organization) => o.id === orgIdFromUrl);
        if (orgFromUrl) {
          setSelectedOrg(orgFromUrl);
          return;
        }
      }

      if (!selectedOrg && orgs.length > 0) {
        setSelectedOrg(orgs[0]);
      } else if (selectedOrg) {
        const updatedOrg = orgs.find((o: Organization) => o.id === selectedOrg.id);
        if (updatedOrg) {
          setSelectedOrg(updatedOrg);
        } else if (orgs.length > 0) {
          setSelectedOrg(orgs[0]);
        } else {
          setSelectedOrg(null);
        }
      }
    } catch (error) {
      console.error('Failed to load organizations:', error);
      setOrganizations([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOrganizations();
  }, []);

  useEffect(() => {
    const orgIdFromUrl = searchParams.get('org');
    if (orgIdFromUrl && organizations.length > 0) {
      const org = organizations.find((o: Organization) => o.id === orgIdFromUrl);
      if (org && org.id !== selectedOrg?.id) {
        setSelectedOrg(org);
      }
    }
  }, [searchParams, organizations]);

  const handleOrgChange = (orgId: string) => {
    const org = organizations.find((o: Organization) => o.id === orgId);
    setSelectedOrg(org || null);
    if (org) {
      setSearchParams({ org: orgId });
    }
  };

  const handleTabChange = (value: string) => {
    const tab = value as ComplianceTab;
    let path = `/admin/compliance/${tab}`;
    if (selectedOrg) {
      navigate(`${path}?org=${selectedOrg.id}`);
    } else {
      navigate(path);
    }
  };

  // Sanctions tab is global, all others need an org
  const needsOrg = activeTab !== 'sanctions';
  const blockedWithoutOrg = needsOrg && !selectedOrg;

  return (
    <ComplianceOrgContext.Provider
      value={{ selectedOrg, setSelectedOrg, organizations }}
    >
      <Card className="animate-fade-in">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#F5F3FF] flex items-center justify-center">
                <Scale className="w-5 h-5 text-[#8950FA]" />
              </div>
              <div>
                <CardTitle className="text-lg">Compliance</CardTitle>
                <p className="text-sm text-[#6B7280] mt-0.5">
                  Travel rule enforcement, token prices, and sanctions
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-sm text-[#6B7280]">Scope:</span>
              {loading ? (
                <div className="flex items-center gap-2 text-[#94A3B8]">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Loading...</span>
                </div>
              ) : !needsOrg ? (
                <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-[#F1F5F9] text-[#6B7280]">
                  <Globe className="w-4 h-4" />
                  <span className="text-sm">Global (all organizations)</span>
                </div>
              ) : organizations.length === 0 ? (
                <Badge variant="outline" className="text-[#6B7280]">
                  No organizations
                </Badge>
              ) : (
                <Select
                  value={selectedOrg?.id || ''}
                  onValueChange={handleOrgChange}
                >
                  <SelectTrigger className="w-[280px]">
                    <SelectValue placeholder="Select organization" />
                  </SelectTrigger>
                  <SelectContent>
                    {organizations.map(org => (
                      <SelectItem key={org.id} value={org.id}>
                        <div className="flex items-center gap-2 whitespace-nowrap">
                          <Building2 className="w-4 h-4 text-[#94A3B8] shrink-0" />
                          <span className="truncate">{org.name}</span>
                          <span className="text-[#94A3B8] text-xs shrink-0">
                            ({org.slug})
                          </span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent className="pt-0">
          <Tabs value={activeTab} onValueChange={handleTabChange}>
            <TabsList className="w-full justify-start mb-4">
              <TabsTrigger value="config" className="gap-2">
                <Settings className="w-4 h-4" />
                <span>Config</span>
              </TabsTrigger>
              <TabsTrigger value="tokens" className="gap-2">
                <Coins className="w-4 h-4" />
                <span>Token Prices</span>
              </TabsTrigger>
              <TabsTrigger value="travel-rules" className="gap-2">
                <FileText className="w-4 h-4" />
                <span>Travel Rules</span>
              </TabsTrigger>
              <TabsTrigger value="sanctions" className="gap-2">
                <ShieldBan className="w-4 h-4" />
                <span>Sanctions</span>
              </TabsTrigger>
              <TabsTrigger value="logs" className="gap-2">
                <ScrollText className="w-4 h-4" />
                <span>Logs</span>
              </TabsTrigger>
            </TabsList>
          </Tabs>

          {blockedWithoutOrg ? <NoOrgSelected /> : <Outlet />}
        </CardContent>
      </Card>
    </ComplianceOrgContext.Provider>
  );
}

function NoOrgSelected() {
  return (
    <div className="text-center py-12">
      <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#F1F5F9] flex items-center justify-center">
        <Building2 className="w-8 h-8 text-[#94A3B8]" />
      </div>
      <p className="text-[#6B7280] mb-2">No organization selected</p>
      <p className="text-[#94A3B8] text-sm">
        Select an organization from the dropdown above to manage compliance settings
      </p>
    </div>
  );
}
