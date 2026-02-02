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
  Building2,
  Users,
  Shield,
  FolderTree,
  FileCode2,
  Loader2,
  Globe,
  Info,
  ChevronDown,
  ChevronUp,
  Hash,
} from 'lucide-react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';

type RBACTab = 'organizations' | 'groups' | 'users' | 'contracts' | 'preregistered';

// Context for sharing organization selection across sub-tabs
interface OrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
  refreshOrgs: () => Promise<void>;
}

export const OrgContext = createContext<OrgContextType | null>(null);

export function useOrgContext() {
  const context = useContext(OrgContext);
  if (!context) {
    throw new Error('useOrgContext must be used within RBACManager');
  }
  return context;
}

export default function RBACManager() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [showHowItWorks, setShowHowItWorks] = useState(false);

  // Derive active tab from URL
  const getActiveTab = (): RBACTab => {
    const path = location.pathname;
    if (path.includes('/groups')) return 'groups';
    if (path.includes('/users')) return 'users';
    if (path.includes('/preregistered')) return 'preregistered';
    if (path.includes('/contracts')) return 'contracts';
    return 'organizations';
  };

  const activeTab = getActiveTab();

  const loadOrganizations = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list();
      const orgs = response.data || [];
      setOrganizations(orgs);

      // Check for org in URL params
      const orgIdFromUrl = searchParams.get('org');
      if (orgIdFromUrl) {
        const orgFromUrl = orgs.find(o => o.id === orgIdFromUrl);
        if (orgFromUrl) {
          setSelectedOrg(orgFromUrl);
          return;
        }
      }

      // Auto-select first org if none selected
      if (!selectedOrg && orgs.length > 0) {
        setSelectedOrg(orgs[0]);
      } else if (selectedOrg) {
        // Refresh the selected org data
        const updatedOrg = orgs.find(o => o.id === selectedOrg.id);
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

  // Sync org from URL when search params change
  useEffect(() => {
    const orgIdFromUrl = searchParams.get('org');
    if (orgIdFromUrl && organizations.length > 0) {
      const org = organizations.find(o => o.id === orgIdFromUrl);
      if (org && org.id !== selectedOrg?.id) {
        setSelectedOrg(org);
      }
    }
  }, [searchParams, organizations]);

  const handleOrgChange = (orgId: string) => {
    const org = organizations.find(o => o.id === orgId);
    setSelectedOrg(org || null);
    // Update URL with new org
    if (org) {
      setSearchParams({ org: orgId });
    }
  };

  const handleTabChange = (value: string) => {
    const tab = value as RBACTab;
    const orgRequiredTabs: RBACTab[] = ['groups', 'contracts', 'preregistered'];
    const needsOrg = orgRequiredTabs.includes(tab);

    let path = `/admin/rbac/${tab === 'organizations' ? 'organizations' : tab}`;
    if (needsOrg && selectedOrg) {
      navigate(`${path}?org=${selectedOrg.id}`);
    } else {
      navigate(path);
    }
  };

  // Tabs that require org selection
  const orgRequiredTabs: RBACTab[] = ['groups', 'users', 'contracts', 'preregistered'];
  const requiresOrg = orgRequiredTabs.includes(activeTab);

  return (
    <OrgContext.Provider
      value={{
        selectedOrg,
        setSelectedOrg,
        organizations,
        refreshOrgs: loadOrganizations,
      }}
    >
      <Card className="animate-fade-in" data-testid="rbac-manager">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#F5F3FF] flex items-center justify-center">
                <Shield className="w-5 h-5 text-[#8950FA]" />
              </div>
              <div>
                <CardTitle className="text-lg" data-testid="rbac-title">Access Control</CardTitle>
                <p className="text-sm text-[#6B7280] mt-0.5">
                  Manage organizations, groups, roles, and permissions
                </p>
              </div>
            </div>

            {/* Organization Selector - always visible, disabled on global tabs */}
            <div className="flex items-center gap-3">
              <span className="text-sm text-[#6B7280]">Scope:</span>
              {loading ? (
                <div className="flex items-center gap-2 text-[#94A3B8]">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Loading...</span>
                </div>
              ) : !requiresOrg ? (
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
                  <SelectTrigger className="w-[280px]" aria-label="Select organization scope" data-testid="org-selector">
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
          {/* How It Works - Collapsible */}
          <div className="mb-4">
            <button
              onClick={() => setShowHowItWorks(!showHowItWorks)}
              className="flex items-center gap-2 text-sm text-[#6B7280] hover:text-[#374151] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8950FA]/40 rounded-md px-2 py-1 -ml-2"
              aria-expanded={showHowItWorks}
              aria-controls="how-permissions-work"
            >
              <Info className="w-4 h-4" aria-hidden="true" />
              <span>How permissions work</span>
              {showHowItWorks ? (
                <ChevronUp className="w-4 h-4" aria-hidden="true" />
              ) : (
                <ChevronDown className="w-4 h-4" aria-hidden="true" />
              )}
            </button>
            {showHowItWorks && (
              <div id="how-permissions-work" className="mt-3 p-4 rounded-lg bg-[#F1F5F9] border border-[#E2E8F0] text-sm animate-fade-in">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h4 className="font-medium text-[#374151] mb-2">Permission Model</h4>
                    <ul className="space-y-1.5 text-[#6B7280] text-xs">
                      <li className="flex items-start gap-2">
                        <Building2 className="w-3.5 h-3.5 mt-0.5 text-[#8950FA] shrink-0" />
                        <span><strong className="text-[#374151]">Organizations</strong> are top-level tenants</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <FolderTree className="w-3.5 h-3.5 mt-0.5 text-[#8950FA] shrink-0" />
                        <span><strong className="text-[#374151]">Groups</strong> define RPC methods, rate limits, and default claims</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <FileCode2 className="w-3.5 h-3.5 mt-0.5 text-[#8950FA] shrink-0" />
                        <span><strong className="text-[#374151]">Contracts</strong> with grants define per-contract claims (read, write, admin, upgrade)</span>
                      </li>
                    </ul>
                  </div>
                  <div>
                    <h4 className="font-medium text-[#374151] mb-2">How Users Get Permissions</h4>
                    <ul className="space-y-1.5 text-[#6B7280] text-xs">
                      <li className="flex items-start gap-2">
                        <span className="text-[#8950FA] font-mono shrink-0">1.</span>
                        <span>Add a <strong className="text-[#374151]">User</strong> to a <strong className="text-[#374151]">Group</strong></span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-[#8950FA] font-mono shrink-0">2.</span>
                        <span>User inherits Group's allowed methods, rate limits, and default claims</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-[#8950FA] font-mono shrink-0">3.</span>
                        <span>Contract grants give specific claims for registered contracts</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          <Tabs value={activeTab} onValueChange={handleTabChange} data-testid="rbac-tabs">
            <TabsList className="w-full justify-start mb-4">
              <TabsTrigger value="organizations" className="gap-2" data-testid="tab-organizations">
                <Building2 className="w-4 h-4" />
                <span>Organizations</span>
              </TabsTrigger>
              <TabsTrigger value="groups" className="gap-2" data-testid="tab-groups">
                <FolderTree className="w-4 h-4" />
                <span>Groups</span>
              </TabsTrigger>
              <TabsTrigger value="users" className="gap-2" data-testid="tab-users">
                <Users className="w-4 h-4" />
                <span>Users</span>
              </TabsTrigger>
              <TabsTrigger value="contracts" className="gap-2" data-testid="tab-contracts">
                <FileCode2 className="w-4 h-4" />
                <span>Contracts</span>
              </TabsTrigger>
              <TabsTrigger value="preregistered" className="gap-2" data-testid="tab-preregistered">
                <Hash className="w-4 h-4" />
                <span>Pre-registered</span>
              </TabsTrigger>
            </TabsList>
          </Tabs>

          {/* Render nested route content */}
          {requiresOrg && !selectedOrg ? <NoOrgSelected /> : <Outlet />}
        </CardContent>
      </Card>
    </OrgContext.Provider>
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
        Select an organization from the dropdown above to manage this resource
      </p>
    </div>
  );
}
