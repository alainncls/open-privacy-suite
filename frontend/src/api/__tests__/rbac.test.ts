import { describe, it, expect } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { rbacApi } from '../rbac';
import {
  mockOrganization,
  mockGroup,
  mockRole,
  mockUser,
  mockContract,
  mockGroupPermissions,
  mockMembershipWithDetails,
  mockEffectivePermissions,
} from '@/test/mocks/handlers';

describe('RBAC API', () => {
  describe('Organizations', () => {
    describe('list', () => {
      it('should list all organizations', async () => {
        const response = await rbacApi.orgs.list();
        expect(response.data).toHaveLength(1);
        expect(response.data[0].slug).toBe(mockOrganization.slug);
      });

      it('should handle empty list', async () => {
        server.use(
          http.get('/api/orgs', () => {
            return HttpResponse.json([]);
          })
        );

        const response = await rbacApi.orgs.list();
        expect(response.data).toHaveLength(0);
      });
    });

    describe('get', () => {
      it('should get organization by ID', async () => {
        const response = await rbacApi.orgs.get('org-1');
        expect(response.data.id).toBe(mockOrganization.id);
        expect(response.data.name).toBe(mockOrganization.name);
      });

      it('should handle not found', async () => {
        await expect(rbacApi.orgs.get('nonexistent')).rejects.toThrow();
      });
    });

    describe('create', () => {
      it('should create a new organization', async () => {
        const response = await rbacApi.orgs.create({
          slug: 'new-org',
          name: 'New Organization',
        });

        expect(response.data.id).toBe('org-new');
        expect(response.data.slug).toBe('new-org');
        expect(response.data.name).toBe('New Organization');
      });
    });

    describe('update', () => {
      it('should update organization', async () => {
        const response = await rbacApi.orgs.update('org-1', {
          name: 'Updated Name',
        });

        expect(response.data.name).toBe('Updated Name');
      });
    });

    describe('delete', () => {
      it('should delete organization', async () => {
        await expect(rbacApi.orgs.delete('org-1')).resolves.not.toThrow();
      });
    });
  });

  describe('Groups', () => {
    describe('list', () => {
      it('should list groups for organization', async () => {
        const response = await rbacApi.groups.list('org-1');
        expect(response.data).toHaveLength(1);
        expect(response.data[0].slug).toBe(mockGroup.slug);
      });
    });

    describe('get', () => {
      it('should get group by ID', async () => {
        const response = await rbacApi.groups.get('org-1', 'group-1');
        expect(response.data.id).toBe(mockGroup.id);
        expect(response.data.name).toBe(mockGroup.name);
      });
    });

    describe('create', () => {
      it('should create a new group', async () => {
        const response = await rbacApi.groups.create('org-1', {
          slug: 'new-group',
          name: 'New Group',
          description: 'A new group',
        });

        expect(response.data.id).toBe('group-new');
        expect(response.data.slug).toBe('new-group');
      });

      it('should create group with parent', async () => {
        const response = await rbacApi.groups.create('org-1', {
          slug: 'child-group',
          name: 'Child Group',
          parent_id: 'group-1',
        });

        expect(response.data.id).toBe('group-new');
      });
    });

    describe('update', () => {
      it('should update group', async () => {
        const response = await rbacApi.groups.update('org-1', 'group-1', {
          name: 'Updated Group',
        });

        expect(response.data.name).toBe('Updated Group');
      });
    });

    describe('delete', () => {
      it('should delete group', async () => {
        await expect(
          rbacApi.groups.delete('org-1', 'group-1')
        ).resolves.not.toThrow();
      });
    });

    describe('permissions', () => {
      it('should get group permissions', async () => {
        const response = await rbacApi.groups.getPermissions('org-1', 'group-1');
        expect(response.data.allow_methods).toEqual(
          mockGroupPermissions.allow_methods
        );
      });

      it('should set group permissions', async () => {
        const response = await rbacApi.groups.setPermissions('org-1', 'group-1', {
          allow_methods: ['eth_call', 'eth_sendTransaction'],
          allow_addresses: ['0xabc'],
        });

        expect(response.data.allow_methods).toContain('eth_call');
        expect(response.data.allow_methods).toContain('eth_sendTransaction');
      });
    });
  });

  describe('Roles', () => {
    describe('list', () => {
      it('should list roles for organization', async () => {
        const response = await rbacApi.roles.list('org-1');
        expect(response.data).toHaveLength(1);
        expect(response.data[0].name).toBe(mockRole.name);
      });
    });

    describe('get', () => {
      it('should get role by ID', async () => {
        const response = await rbacApi.roles.get('org-1', 'role-1');
        expect(response.data.id).toBe(mockRole.id);
        expect(response.data.claims).toEqual(mockRole.claims);
      });
    });

    describe('create', () => {
      it('should create a new role', async () => {
        const response = await rbacApi.roles.create('org-1', {
          name: 'New Role',
          description: 'A new role',
          claims: ['reader', 'writer'],
        });

        expect(response.data.id).toBe('role-new');
        expect(response.data.name).toBe('New Role');
        expect(response.data.claims).toContain('reader');
      });
    });

    describe('update', () => {
      it('should update role', async () => {
        const response = await rbacApi.roles.update('org-1', 'role-1', {
          claims: ['reader', 'writer', 'deployer'],
        });

        expect(response.data.claims).toContain('deployer');
      });
    });

    describe('delete', () => {
      it('should delete role', async () => {
        await expect(
          rbacApi.roles.delete('org-1', 'role-1')
        ).resolves.not.toThrow();
      });
    });
  });

  describe('Users', () => {
    describe('list', () => {
      it('should list users with pagination', async () => {
        const response = await rbacApi.users.list(10, 0);
        expect(response.data).toHaveLength(1);
        expect(response.data[0].external_id).toBe(mockUser.external_id);
      });
    });

    describe('get', () => {
      it('should get user by ID', async () => {
        const response = await rbacApi.users.get('user-1');
        expect(response.data.id).toBe(mockUser.id);
        expect(response.data.kyc).toBe(mockUser.kyc);
      });
    });

    describe('update', () => {
      it('should update user', async () => {
        const response = await rbacApi.users.update('user-1', {
          banned: true,
          note: 'Banned for testing',
        });

        expect(response.data.banned).toBe(true);
        expect(response.data.note).toBe('Banned for testing');
      });
    });

    describe('memberships', () => {
      it('should get user memberships', async () => {
        const response = await rbacApi.users.getMemberships('user-1');
        expect(response.data).toHaveLength(1);
        expect(response.data[0].group.id).toBe(
          mockMembershipWithDetails.group.id
        );
      });

      it('should create membership', async () => {
        const response = await rbacApi.users.createMembership('user-1', {
          group_id: 'group-1',
          role_id: 'role-1',
        });

        expect(response.data.id).toBe('membership-new');
        expect(response.data.group_id).toBe('group-1');
      });

      it('should delete membership', async () => {
        await expect(
          rbacApi.users.deleteMembership('user-1', 'membership-1')
        ).resolves.not.toThrow();
      });
    });

    describe('effective permissions', () => {
      it('should get effective permissions', async () => {
        const response = await rbacApi.users.getEffectivePermissions('user-1');
        expect(response.data.allow_methods).toEqual(
          mockEffectivePermissions.allow_methods
        );
        expect(response.data.claims).toEqual(mockEffectivePermissions.claims);
      });

      it('should get effective permissions for specific org', async () => {
        const response = await rbacApi.users.getEffectivePermissions(
          'user-1',
          'test-org'
        );
        expect(response.data.org_id).toBe(mockEffectivePermissions.org_id);
      });
    });
  });

  describe('Contracts', () => {
    describe('list', () => {
      it('should list contracts for organization', async () => {
        const response = await rbacApi.contracts.list('org-1');
        expect(response.data).toHaveLength(1);
        expect(response.data[0].contract_address).toBe(
          mockContract.contract_address
        );
      });
    });

    describe('create', () => {
      it('should create contract ownership', async () => {
        const response = await rbacApi.contracts.create('org-1', {
          contract_address: '0xnewcontract',
          owner_group_id: 'group-1',
        });

        expect(response.data.id).toBe('contract-new');
        expect(response.data.contract_address).toBe('0xnewcontract');
      });
    });

    describe('update', () => {
      it('should update contract ownership', async () => {
        const response = await rbacApi.contracts.update(
          'org-1',
          '0x1234567890123456789012345678901234567890',
          {
            metadata: { updated: true },
          }
        );

        expect(response.data.metadata).toHaveProperty('updated');
      });
    });

    describe('delete', () => {
      it('should delete contract ownership', async () => {
        await expect(
          rbacApi.contracts.delete(
            'org-1',
            '0x1234567890123456789012345678901234567890'
          )
        ).resolves.not.toThrow();
      });
    });
  });

  describe('Utilities', () => {
    describe('checkAccess', () => {
      it('should check access for user', async () => {
        const response = await rbacApi.utils.checkAccess({
          user_external_id: 'did:test:user',
          method: 'eth_call',
        });

        expect(response.data.allowed).toBe(true);
        expect(response.data.claims).toContain('reader');
      });

      it('should check access with target address', async () => {
        const response = await rbacApi.utils.checkAccess({
          user_external_id: 'did:test:user',
          method: 'eth_call',
          target_address: '0x1234',
        });

        expect(response.data.allowed).toBe(true);
      });
    });

    describe('getCacheStats', () => {
      it('should get cache statistics', async () => {
        const response = await rbacApi.utils.getCacheStats();

        expect(response.data.hits).toBe(100);
        expect(response.data.misses).toBe(10);
        expect(response.data.size).toBe(50);
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors', async () => {
      server.use(
        http.get('/api/orgs', () => {
          return HttpResponse.error();
        })
      );

      await expect(rbacApi.orgs.list()).rejects.toThrow();
    });

    it('should handle 500 errors', async () => {
      server.use(
        http.get('/api/orgs', () => {
          return HttpResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
          );
        })
      );

      await expect(rbacApi.orgs.list()).rejects.toThrow();
    });

    it('should handle 403 forbidden', async () => {
      server.use(
        http.post('/api/orgs', () => {
          return HttpResponse.json(
            { error: 'Forbidden' },
            { status: 403 }
          );
        })
      );

      await expect(
        rbacApi.orgs.create({ slug: 'test', name: 'Test' })
      ).rejects.toThrow();
    });
  });
});
