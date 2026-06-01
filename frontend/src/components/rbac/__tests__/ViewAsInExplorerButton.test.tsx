import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ViewAsInExplorerButton } from '../ViewAsInExplorerButton';
import { resolveExplorerUrl } from '@/lib/explorerUrl';

const TARGET = 'did:iden3:privado:test:abc123';

afterEach(() => {
  vi.unstubAllEnvs();
  delete window.__runtimeConfig;
});

describe('resolveExplorerUrl', () => {
  it('uses the runtime-config value when present', () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'https://explorer.devnet.example.com',
    };
    expect(resolveExplorerUrl()).toBe('https://explorer.devnet.example.com');
  });

  it('trims trailing slashes', () => {
    window.__runtimeConfig = { VITE_BLOCK_EXPLORER_URL: 'https://x.example.com//' };
    expect(resolveExplorerUrl()).toBe('https://x.example.com');
  });

  it('returns empty (no localhost fallback) when unconfigured in a production build', () => {
    vi.stubEnv('DEV', false);
    window.__runtimeConfig = {};
    expect(resolveExplorerUrl()).toBe('');
  });

  it('falls back to the local explorer only in the dev server', () => {
    vi.stubEnv('DEV', true);
    window.__runtimeConfig = {};
    expect(resolveExplorerUrl()).toBe('http://localhost:3001');
  });

  it('rejects non-http(s) schemes (defence-in-depth)', () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'javascript:alert(1)',
    };
    expect(resolveExplorerUrl()).toBe('');
  });

  it('rejects values that are not absolute URLs', () => {
    window.__runtimeConfig = { VITE_BLOCK_EXPLORER_URL: 'not a url' };
    expect(resolveExplorerUrl()).toBe('');
  });
});

describe('ViewAsInExplorerButton', () => {
  it('is disabled when the explorer URL is not configured (prod)', () => {
    vi.stubEnv('DEV', false);
    window.__runtimeConfig = {};
    render(<ViewAsInExplorerButton targetDID={TARGET} variant="inline" />);
    expect(screen.getByRole('button')).toBeDisabled();
  });

  it('navigates same-tab to the explorer /view-as handoff when configured', async () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'https://explorer.devnet.example.com',
    };
    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, set href(v: string) { hrefSetter(v); } },
    });

    render(<ViewAsInExplorerButton targetDID={TARGET} variant="inline" />);
    await userEvent.click(screen.getByRole('button'));

    expect(hrefSetter).toHaveBeenCalledWith(
      `https://explorer.devnet.example.com/view-as?did=${encodeURIComponent(TARGET)}`,
    );

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    });
  });
});
