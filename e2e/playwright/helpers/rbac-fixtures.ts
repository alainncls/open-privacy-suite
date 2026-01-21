import { randomUUID } from 'crypto';
import { APIRequestContext } from '@playwright/test';
import {
  RBACApiClient,
  Organization,
  Group,
  User,
  UserMembership,
  Contract,
  Claim,
} from './rbac-api.js';
import { getJWTToken } from './auth.js';

/**
 * Hierarchy definition for creating nested group structures.
 */
export interface HierarchyNode {
  slug: string;
  name: string;
  access?: {
    allowed_methods?: string[];
    default_claims?: Claim[];
    rate_limit_rps?: number;
    rate_limit_daily?: number;
  };
  children?: HierarchyNode[];
}

/**
 * Options for creating a user with membership.
 */
export interface CreateUserOptions {
  kyc?: boolean;
  banned?: boolean;
  /**
   * If true, keep the user's default membership to the default group.
   * By default, the default membership is removed so that only the custom membership applies.
   * Set to true when testing multiple memberships behavior.
   */
  keepDefaultMembership?: boolean;
}

/**
 * RBACTestFixture provides test data factories with automatic cleanup.
 * Each test should create its own fixture instance to ensure isolation.
 */
export class RBACTestFixture {
  readonly testId: string;
  readonly rbac: RBACApiClient;

  // Tracked resources for cleanup
  private orgs: Organization[] = [];
  private groups: { orgId: string; group: Group }[] = [];
  private users: User[] = [];
  private memberships: { userId: string; membership: UserMembership }[] = [];
  private contracts: { orgId: string; address: string }[] = [];

  constructor(request: APIRequestContext) {
    this.testId = randomUUID().slice(0, 8);
    this.rbac = new RBACApiClient(request);
  }

  /**
   * Generate a unique slug for test isolation.
   */
  slug(base: string): string {
    return `${base}_${this.testId}`;
  }

  /**
   * Generate a unique DID for test isolation.
   */
  did(): string {
    const uniquePart = randomUUID().slice(0, 8);
    return `did:privado:test_${this.testId}_${uniquePart}`;
  }

  /**
   * Generate a unique Ethereum address for test isolation.
   */
  contractAddress(): string {
    const bytes = randomUUID().replace(/-/g, '').slice(0, 40);
    return `0x${bytes}`;
  }

  // === Organization Methods ===

  /**
   * Create an organization and track for cleanup.
   */
  async createOrg(slugBase: string, name?: string): Promise<Organization> {
    const orgSlug = this.slug(slugBase);
    const org = await this.rbac.createOrganization({
      slug: orgSlug,
      name: name ?? `Test Org ${orgSlug}`,
    });
    this.orgs.push(org);
    return org;
  }

  // === Group Methods ===

  /**
   * Create a group and track for cleanup.
   */
  async createGroup(orgId: string, slugBase: string, opts?: {
    name?: string;
    description?: string;
    parentId?: string;
  }): Promise<Group> {
    const groupSlug = this.slug(slugBase);
    const group = await this.rbac.createGroup(orgId, {
      slug: groupSlug,
      name: opts?.name ?? `Test Group ${groupSlug}`,
      description: opts?.description ?? '',
      parent_id: opts?.parentId,
    });
    this.groups.push({ orgId, group });
    return group;
  }

  /**
   * Create a complete group hierarchy from a tree definition.
   * Returns a map from slug to Group for easy access.
   */
  async createGroupHierarchy(orgId: string, nodes: HierarchyNode[]): Promise<Map<string, Group>> {
    const result = new Map<string, Group>();

    const createNode = async (node: HierarchyNode, parentId?: string): Promise<void> => {
      const group = await this.createGroup(orgId, node.slug, {
        name: node.name,
        parentId,
      });
      result.set(node.slug, group);

      // Set access settings if provided
      if (node.access) {
        await this.rbac.setGroupAccess(orgId, group.id, node.access);
      }

      // Recursively create children
      if (node.children) {
        for (const child of node.children) {
          await createNode(child, group.id);
        }
      }
    };

    for (const node of nodes) {
      await createNode(node);
    }

    return result;
  }

  // === User Methods ===

  /**
   * Create a user by authenticating them (which creates the user via EnsureUserExists).
   * Returns the user after it's been created in the system.
   */
  async createUser(request: APIRequestContext, opts?: { kyc?: boolean; banned?: boolean }): Promise<{
    user: User;
    did: string;
    token: string;
  }> {
    const userDID = this.did();

    // Authenticate to create the user via EnsureUserExists
    const token = await getJWTToken(request, userDID);

    // Find the created user
    const user = await this.rbac.findUserByExternalId(userDID);
    if (!user) {
      throw new Error(`User not found after auth: ${userDID}`);
    }

    this.users.push(user);

    // Update KYC and banned status if specified
    if (opts?.kyc !== undefined || opts?.banned !== undefined) {
      const updated = await this.rbac.updateUser(user.id, {
        kyc: opts?.kyc,
        banned: opts?.banned,
      });
      return { user: updated, did: userDID, token };
    }

    return { user, did: userDID, token };
  }

  /**
   * Create a user with a membership to a specific group.
   * By default, removes the auto-created default membership so only the custom group applies.
   */
  async createUserWithMembership(
    request: APIRequestContext,
    groupId: string,
    opts?: CreateUserOptions
  ): Promise<{
    user: User;
    did: string;
    token: string;
    membership: UserMembership;
  }> {
    const { user, did, token } = await this.createUser(request, {
      kyc: opts?.kyc ?? true,
      banned: opts?.banned ?? false,
    });

    // Remove default membership unless explicitly kept
    // Default group ID is 00000000-0000-0000-0000-000000000001
    const DEFAULT_GROUP_ID = '00000000-0000-0000-0000-000000000001';
    if (!opts?.keepDefaultMembership) {
      const memberships = await this.rbac.listUserMemberships(user.id);
      for (const m of memberships) {
        if (m.membership.group_id === DEFAULT_GROUP_ID) {
          await this.rbac.deleteMembership(user.id, m.membership.id);
        }
      }
    }

    // Create membership
    const membership = await this.rbac.createMembership(user.id, {
      group_id: groupId,
    });
    this.memberships.push({ userId: user.id, membership });

    return { user, did, token, membership };
  }

  /**
   * Add an additional membership for an existing user.
   */
  async addMembership(
    userId: string,
    groupId: string
  ): Promise<UserMembership> {
    const membership = await this.rbac.createMembership(userId, {
      group_id: groupId,
    });
    this.memberships.push({ userId, membership });
    return membership;
  }

  // === Contract Methods ===

  /**
   * Create a contract and track for cleanup.
   */
  async createContract(
    orgId: string,
    opts?: {
      address?: string;
      name?: string;
    }
  ): Promise<Contract> {
    const address = opts?.address ?? this.contractAddress();
    const contract = await this.rbac.createContract(orgId, {
      address,
      name: opts?.name,
    });
    this.contracts.push({ orgId, address });
    return contract;
  }

  // === Cleanup ===

  /**
   * Clean up all tracked resources in reverse order of creation.
   * This ensures proper deletion order (children before parents).
   */
  async cleanup(): Promise<void> {
    // Delete contracts first
    for (const { orgId, address } of [...this.contracts].reverse()) {
      try {
        await this.rbac.deleteContract(orgId, address);
      } catch {
        // Ignore cleanup errors
      }
    }

    // Delete memberships
    for (const { userId, membership } of [...this.memberships].reverse()) {
      try {
        await this.rbac.deleteMembership(userId, membership.id);
      } catch {
        // Ignore cleanup errors
      }
    }

    // We don't delete users - they remain in the system
    // but are isolated by unique DIDs

    // Delete groups (children first due to reverse order)
    for (const { orgId, group } of [...this.groups].reverse()) {
      try {
        await this.rbac.deleteGroup(orgId, group.id);
      } catch {
        // Ignore cleanup errors
      }
    }

    // We don't delete organizations to avoid affecting other tests
    // Organizations with unique slugs are effectively isolated

    // Clear tracked resources
    this.contracts = [];
    this.memberships = [];
    this.users = [];
    this.groups = [];
    this.orgs = [];
  }
}
