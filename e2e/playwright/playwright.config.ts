import { defineConfig, devices } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 8 : undefined,
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['junit', { outputFile: 'test-results/junit.xml' }],
    ['list'],
  ],
  use: {
    trace: 'on-first-retry',
  },
  globalSetup: './global-setup.ts',
  timeout: 30000,
  expect: {
    timeout: 5000,
  },
  projects: [
    // API tests (existing)
    {
      name: 'api',
      testMatch: /^(?!.*\/ui\/).*\.spec\.ts$/,
      use: {
        baseURL: PROXY_URL,
        extraHTTPHeaders: {
          'Content-Type': 'application/json',
          'X-Admin-Token': process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token',
        },
      },
    },
    // UI tests (new)
    {
      name: 'ui',
      testDir: './tests/ui',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: FRONTEND_URL,
        viewport: { width: 1280, height: 720 },
        actionTimeout: 10000,
        navigationTimeout: 15000,
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
      },
    },
  ],
});
