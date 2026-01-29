import { Page, expect } from '@playwright/test';
import { selectors } from './selectors';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * Perform mock login via the UI mock login button.
 * Requires VITE_ALLOW_MOCK_LOGIN=true in the frontend environment.
 *
 * @param page - Playwright page object
 */
export async function mockLoginViaUI(page: Page): Promise<void> {
  // Navigate to login page
  await page.goto('/login');

  // Wait for the login page to be visible
  await expect(page.locator(selectors.login.page)).toBeVisible({ timeout: 10000 });

  // Wait for dev tools to appear (indicates mock login is available)
  const devTools = page.locator(selectors.login.devTools);
  await expect(devTools).toBeVisible({ timeout: 10000 });

  // Click the mock login button
  const mockLoginBtn = page.locator(selectors.login.mockLoginBtn);
  await expect(mockLoginBtn).toBeVisible();
  await mockLoginBtn.click();

  // Wait for success state or redirect
  // The login will redirect to /link-wallet on success
  await expect(page).toHaveURL(/\/(link-wallet|admin)/, { timeout: 15000 });
}

/**
 * Perform mock login via direct API calls and inject tokens into localStorage.
 * This is faster than UI-based login and useful for setting up authenticated state.
 *
 * @param page - Playwright page object
 * @param userDID - Optional DID for the mock user (defaults to a generated DID)
 */
export async function mockLoginViaAPI(page: Page, userDID?: string): Promise<void> {
  const did = userDID || `did:privado:dev_${Date.now()}`;

  // Get tokens via API
  const tokens = await getAuthTokens(did);

  // Set up localStorage with auth tokens before navigating
  await page.addInitScript((authData) => {
    const storageKey = 'privacy_proxy_auth';
    const auth = {
      accessToken: authData.accessToken,
      refreshToken: authData.refreshToken,
      expiresAt: Date.now() + authData.expiresIn * 1000,
    };
    localStorage.setItem(storageKey, JSON.stringify(auth));
  }, tokens);
}

/**
 * Get auth tokens via the backend API using mock authentication.
 * This directly calls the auth endpoints to get JWT tokens.
 *
 * @param userDID - The DID to authenticate as
 * @returns Auth tokens
 */
export async function getAuthTokens(userDID: string): Promise<AuthTokens> {
  // Step 1: Create auth request to get session ID
  const authRequestResponse = await fetch(`${ADMIN_URL}/auth/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!authRequestResponse.ok) {
    const body = await authRequestResponse.text();
    throw new Error(`Failed to create auth request: ${authRequestResponse.status} - ${body}`);
  }

  const { session_id } = await authRequestResponse.json();

  // Step 2: Verify with mock JWZ token (dev mode only)
  const verifyResponse = await fetch(`${ADMIN_URL}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id,
      jwz_token: `mock.${userDID}`,
    }),
  });

  if (!verifyResponse.ok) {
    const body = await verifyResponse.text();
    throw new Error(`Failed to verify auth: ${verifyResponse.status} - ${body}`);
  }

  const data = await verifyResponse.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  };
}

/**
 * Check if the user is currently authenticated by examining localStorage.
 *
 * @param page - Playwright page object
 * @returns True if authenticated
 */
export async function isAuthenticated(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const stored = localStorage.getItem('privacy_proxy_auth');
    if (!stored) return false;

    try {
      const auth = JSON.parse(stored);
      return auth.expiresAt > Date.now();
    } catch {
      return false;
    }
  });
}

/**
 * Clear authentication state (logout).
 *
 * @param page - Playwright page object
 */
export async function clearAuth(page: Page): Promise<void> {
  await page.evaluate(() => {
    localStorage.removeItem('privacy_proxy_auth');
  });
}

/**
 * Navigate to admin section after ensuring authentication.
 * If not authenticated, performs mock login first.
 *
 * @param page - Playwright page object
 * @param path - Admin path to navigate to (e.g., '/admin/dashboard')
 */
export async function navigateToAdminAuthenticated(
  page: Page,
  path: string = '/admin/dashboard'
): Promise<void> {
  // First, inject auth tokens via API
  await mockLoginViaAPI(page);

  // Now navigate to the admin page
  await page.goto(path);

  // Wait for admin app to be visible
  await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });
}
