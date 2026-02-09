import '@testing-library/jest-dom';
import { afterAll, afterEach, beforeAll, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import { server } from './mocks/server';

// Suppress React act() warnings from Radix UI animations
// These occur because Radix UI's Presence component triggers state updates
// during dialog open/close animations that happen after tests complete.
// This is a known testing issue with Radix UI and doesn't affect functionality.
const originalConsoleError = console.error;
beforeAll(() => {
  console.error = (...args: unknown[]) => {
    const message = args[0];
    if (
      typeof message === 'string' &&
      message.includes('was not wrapped in act')
    ) {
      return; // Suppress act() warnings
    }
    originalConsoleError(...args);
  };
});

afterAll(() => {
  console.error = originalConsoleError;
});

// Start MSW server before all tests
// Use 'warn' instead of 'error' to avoid failing tests due to cleanup/refetch requests
// that happen after test completion. Tests still pass; unhandled requests are just logged.
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'warn' });
});

// Reset handlers after each test
afterEach(() => {
  server.resetHandlers();
  cleanup();
});

// Close server after all tests
afterAll(() => {
  server.close();
});

// jsdom provides localStorage by default - just clear it between tests
afterEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock pointer capture APIs for Radix UI Select components
// JSDOM doesn't support these APIs which are used by Radix UI
Element.prototype.hasPointerCapture = vi.fn().mockReturnValue(false);
Element.prototype.setPointerCapture = vi.fn();
Element.prototype.releasePointerCapture = vi.fn();

// Mock ResizeObserver (not available in JSDOM)
class ResizeObserverMock {
  observe = vi.fn();
  unobserve = vi.fn();
  disconnect = vi.fn();
}

Object.defineProperty(window, 'ResizeObserver', {
  writable: true,
  value: ResizeObserverMock,
});

// Mock scrollIntoView (not available in JSDOM)
Element.prototype.scrollIntoView = vi.fn();
