import { FullConfig } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
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

async function globalSetup(_config: FullConfig): Promise<void> {
  console.log('Starting global setup...');

  // Wait for proxy backend health endpoint
  await waitForService(`${PROXY_URL}/health`, 'Privacy Proxy');

  console.log('All services ready!');
}

export default globalSetup;
