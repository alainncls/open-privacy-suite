import { randomUUID } from 'crypto';
import { APIRequestContext } from '@playwright/test';
import { createPolicy, deletePolicy, PolicyOptions } from './policy.js';
import { getJWTToken } from './auth.js';

/**
 * TestContext provides test isolation through unique DIDs.
 * Each test gets its own DID, preventing conflicts in parallel execution.
 */
export class TestContext {
  readonly testId: string;
  readonly userDID: string;
  private _accessToken: string | null = null;

  constructor() {
    this.testId = randomUUID().slice(0, 8);
    this.userDID = `did:privado:test_${this.testId}`;
  }

  /**
   * Create a policy for this test's user
   */
  async createPolicy(request: APIRequestContext, opts: PolicyOptions = {}): Promise<void> {
    await createPolicy(request, this.userDID, opts);
  }

  /**
   * Get a JWT token for this test's user
   */
  async getToken(request: APIRequestContext): Promise<string> {
    if (!this._accessToken) {
      this._accessToken = await getJWTToken(request, this.userDID);
    }
    return this._accessToken;
  }

  /**
   * Clean up policy for this test's user
   */
  async cleanup(request: APIRequestContext): Promise<void> {
    await deletePolicy(request, this.userDID);
    this._accessToken = null;
  }
}
