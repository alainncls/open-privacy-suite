import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for demo video recording.
 * Optimized for high-quality 1080p video capture.
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [["html", { open: "never" }], ["list"]],
  timeout: 120000,

  use: {
    baseURL: process.env.BASE_URL || "http://localhost:5173",
    trace: "on",
    screenshot: "on",
    video: {
      mode: "on",
      size: { width: 1920, height: 1080 },
    },
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 2,
    actionTimeout: 15000,
    navigationTimeout: 30000,
  },

  projects: [
    {
      name: "recording",
      use: {
        ...devices["Desktop Chrome"],
        channel: "chrome",
        launchOptions: {
          args: [
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--start-maximized",
          ],
        },
      },
    },
  ],

  webServer: process.env.NO_SERVER
    ? undefined
    : {
        command: "cd ../../frontend && npm run dev",
        url: "http://localhost:5173",
        reuseExistingServer: !process.env.CI,
        timeout: 60000,
      },

  outputDir: "./test-results",
});
