import { useState, useEffect, createContext, useContext } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
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
} from 'lucide-react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';
import OrganizationList from './OrganizationList';
import GroupList from './GroupList';
import RoleList from './RoleList';
import UserList from './UserList';
import ContractList from './ContractList';

type RBACTab = 'organizations' | 'groups' | 'roles' | 'users' | 'contracts';

// Context for sharing organization selection across sub-tabs
interface OrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
  refreshOrgs: () => Promise<void>;
}

const OrgContext = createContext<OrgContextType | null>(null);

export function useOrgContext() {
  const context = useContext(OrgContext);
  if (!context) {
    throw new Error('useOrgContext must be used within RBACManager');
  }
  return context;
}

export default function RBACManager() {
  const [activeTab, setActiveTab] = useState<RBACTab>('organizations');
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);

  const loadOrganizations = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list();
      const orgs = response.data || [];
      setOrganizations(orgs);
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

  const handleOrgChange = (orgId: string) => {
    const org = organizations.find(o => o.id === orgId);
    setSelectedOrg(org || null);
  };

  // Tabs that require org selection
  const orgRequiredTabs: RBACTab[] = ['groups', 'roles', 'contracts'];
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
      <Card className="animate-fade-in">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary-400" />
              </div>
              <div>
                <CardTitle className="text-lg">Access Control</CardTitle>
                <p className="text-sm text-white/50 mt-0.5">
                  Manage organizations, groups, roles, and permissions
                </p>
              </div>
            </div>

            {/* Organization Selector - shown when org is required */}
            {requiresOrg && (
              <div className="flex items-center gap-3">
                <span className="text-sm text-white/60">Organization:</span>
                {loading ? (
                  <div className="flex items-center gap-2 text-white/40">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span className="text-sm">Loading...</span>
                  </div>
                ) : organizations.length === 0 ? (
                  <Badge variant="outline" className="text-white/50">
                    No organizations
                  </Badge>
                ) : (
                  <Select
                    value={selectedOrg?.id || ''}
                    onValueChange={handleOrgChange}
                  >
                    <SelectTrigger className="w-[200px]">
                      <SelectValue placeholder="Select organization" />
                    </SelectTrigger>
                    <SelectContent>
                      {organizations.map(org => (
                        <SelectItem key={org.id} value={org.id}>
                          <div className="flex items-center gap-2">
                            <Building2 className="w-4 h-4 text-white/40" />
                            <span>{org.name}</span>
                            <span className="text-white/40 text-xs">
                              ({org.slug})
                            </span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="pt-0">
          <Tabs
            value={activeTab}
            onValueChange={value => setActiveTab(value as RBACTab)}
          >
            <TabsList className="w-full justify-start mb-4">
              <TabsTrigger value="organizations" className="gap-2">
                <Building2 className="w-4 h-4" />
                <span>Organizations</span>
              </TabsTrigger>
              <TabsTrigger value="groups" className="gap-2">
                <FolderTree className="w-4 h-4" />
                <span>Groups</span>
              </TabsTrigger>
              <TabsTrigger value="roles" className="gap-2">
                <Shield className="w-4 h-4" />
                <span>Roles</span>
              </TabsTrigger>
              <TabsTrigger value="users" className="gap-2">
                <Users className="w-4 h-4" />
                <span>Users</span>
              </TabsTrigger>
              <TabsTrigger value="contracts" className="gap-2">
                <FileCode2 className="w-4 h-4" />
                <span>Contracts</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="organizations">
              <OrganizationList />
            </TabsContent>

            <TabsContent value="groups">
              {!selectedOrg ? (
                <NoOrgSelected />
              ) : (
                <GroupList orgId={selectedOrg.id} />
              )}
            </TabsContent>

            <TabsContent value="roles">
              {!selectedOrg ? (
                <NoOrgSelected />
              ) : (
                <RoleList orgId={selectedOrg.id} />
              )}
            </TabsContent>

            <TabsContent value="users">
              <UserList />
            </TabsContent>

            <TabsContent value="contracts">
              {!selectedOrg ? (
                <NoOrgSelected />
              ) : (
                <ContractList orgId={selectedOrg.id} />
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </OrgContext.Provider>
  );
}

function NoOrgSelected() {
  return (
    <div className="text-center py-12">
      <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
        <Building2 className="w-8 h-8 text-white/30" />
      </div>
      <p className="text-white/50 mb-2">No organization selected</p>
      <p className="text-white/40 text-sm">
        Select an organization from the dropdown above to manage this resource
      </p>
    </div>
  );
}
