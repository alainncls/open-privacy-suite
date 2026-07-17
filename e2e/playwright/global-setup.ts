import { FullConfig } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const MAX_RETRIES = 30;
const RETRY_DELAY_MS = 1000;

async function waitForService(url: string, name: string): Promise<void> {
  console.log(`Waiting for ${name} at ${url}...`);

  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      const response = await fetch(url, { method: 'GET' });
      if (response.ok) {
        console.log(`${name} is ready!`);
        return;
      }
    } catch {
      // Service not ready yet
    }

    await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
  }

  throw new Error(`${name} at ${url} did not become ready after ${MAX_RETRIES} retries`);
}

async function globalSetup(config: FullConfig): Promise<void> {
  console.log('Starting global setup...');

  // Wait for proxy backend health endpoint
  await waitForService(`${PROXY_URL}/health`, 'Open Privacy Suite');

  // Check if any UI tests are being run by examining the projects
  const runningProjects = config.projects.filter(p => {
    // If grep is specified, check if project matches
    return p.name === 'ui' || !p.testDir?.includes('ui');
  });

  const hasUIProject = runningProjects.some(p => p.name === 'ui');

  // Wait for frontend service if FRONTEND_URL is set and UI tests are included
  if (hasUIProject && FRONTEND_URL) {
    try {
      await waitForService(FRONTEND_URL, 'Frontend (Vite)');
    } catch (error) {
      console.warn(`Warning: Frontend not available at ${FRONTEND_URL}. UI tests may fail.`);
      // Don't throw - allow API tests to still run
    }
  }

  console.log('All services ready!');
}

export default globalSetup;
