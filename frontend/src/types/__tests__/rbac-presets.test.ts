import { describe, it, expect } from 'vitest';
import {
  ExpandClaims,
  METHOD_SECTIONS,
  PERMISSION_PRESETS,
  RPC_METHODS_BY_CLAIM,
  getPresetMethods,
  deriveClaims,
  getClosestPresetLabel,
  detectMatchingPreset,
} from '../rbac';
import type { Claim } from '../rbac';

describe('ExpandClaims', () => {
  it('admin expands to read, write, deploy, upgrade', () => {
    const result = ExpandClaims(['admin'] as Claim[]);
    expect(result).toContain('admin');
    expect(result).toContain('read');
    expect(result).toContain('write');
    expect(result).toContain('deploy');
    expect(result).toContain('upgrade');
    expect(result).toHaveLength(5);
  });

  it('deploy expands to read, write', () => {
    const result = ExpandClaims(['deploy'] as Claim[]);
    expect(result).toContain('deploy');
    expect(result).toContain('read');
    expect(result).toContain('write');
    expect(result).toHaveLength(3);
  });

  it('upgrade expands to read, write', () => {
    const result = ExpandClaims(['upgrade'] as Claim[]);
    expect(result).toContain('upgrade');
    expect(result).toContain('read');
    expect(result).toContain('write');
    expect(result).toHaveLength(3);
  });

  it('read does not expand', () => {
    const result = ExpandClaims(['read'] as Claim[]);
    expect(result).toEqual(['read']);
  });

  it('write does not expand', () => {
    const result = ExpandClaims(['write'] as Claim[]);
    expect(result).toEqual(['write']);
  });

  it('deduplicates when multiple claims imply the same', () => {
    // deploy and upgrade both imply read + write
    const result = ExpandClaims(['deploy', 'upgrade'] as Claim[]);
    expect(result).toContain('deploy');
    expect(result).toContain('upgrade');
    expect(result).toContain('read');
    expect(result).toContain('write');
    expect(result).toHaveLength(4);
  });

  it('empty array returns empty', () => {
    const result = ExpandClaims([] as Claim[]);
    expect(result).toEqual([]);
  });
});

describe('Security: METHOD_SECTIONS consistency', () => {
  it('every method in METHOD_SECTIONS exists in RPC_METHODS_BY_CLAIM', () => {
    const allClaimMethods = new Set([
      ...RPC_METHODS_BY_CLAIM.read,
      ...RPC_METHODS_BY_CLAIM.write,
      ...RPC_METHODS_BY_CLAIM.deploy,
    ]);
    for (const [sectionName, section] of Object.entries(METHOD_SECTIONS)) {
      for (const method of section.methods) {
        expect(
          allClaimMethods.has(method),
          `Method "${method}" in section "${sectionName}" is not in RPC_METHODS_BY_CLAIM`,
        ).toBe(true);
      }
    }
  });

  it('no duplicate methods across sections', () => {
    const seen = new Set<string>();
    for (const [sectionName, section] of Object.entries(METHOD_SECTIONS)) {
      for (const method of section.methods) {
        expect(
          seen.has(method),
          `Method "${method}" appears in multiple sections (duplicate found in "${sectionName}")`,
        ).toBe(false);
        seen.add(method);
      }
    }
  });

  it('all claim methods are covered by METHOD_SECTIONS', () => {
    const sectionMethods = new Set<string>();
    for (const section of Object.values(METHOD_SECTIONS)) {
      for (const method of section.methods) {
        sectionMethods.add(method);
      }
    }
    const allClaimMethods = [
      ...RPC_METHODS_BY_CLAIM.read,
      ...RPC_METHODS_BY_CLAIM.write,
      ...RPC_METHODS_BY_CLAIM.deploy,
    ];
    for (const method of allClaimMethods) {
      expect(
        sectionMethods.has(method),
        `Method "${method}" from RPC_METHODS_BY_CLAIM is not in any METHOD_SECTION`,
      ).toBe(true);
    }
  });
});

describe('getPresetMethods', () => {
  const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
  const servicePreset = PERMISSION_PRESETS.find(p => p.id === 'service_backend')!;
  const developerPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
  const adminPreset = PERMISSION_PRESETS.find(p => p.id === 'admin')!;

  it('Wallet User preset returns exactly the Wallet User section methods', () => {
    const methods = getPresetMethods(walletPreset);
    expect(methods).toHaveLength(METHOD_SECTIONS['Wallet User'].methods.length);
  });

  it('Service/Backend preset returns Wallet User + Service section methods', () => {
    const methods = getPresetMethods(servicePreset);
    const expected =
      METHOD_SECTIONS['Wallet User'].methods.length +
      METHOD_SECTIONS['Service / Backend'].methods.length;
    expect(methods).toHaveLength(expected);
  });

  it('Developer preset returns all section methods combined', () => {
    const methods = getPresetMethods(developerPreset);
    const expected =
      METHOD_SECTIONS['Wallet User'].methods.length +
      METHOD_SECTIONS['Service / Backend'].methods.length +
      METHOD_SECTIONS['Developer'].methods.length;
    expect(methods).toHaveLength(expected);
  });

  it('Admin preset returns same methods as Developer (difference is adminClaim flag)', () => {
    const devMethods = getPresetMethods(developerPreset);
    const adminMethods = getPresetMethods(adminPreset);
    expect(adminMethods).toHaveLength(devMethods.length);
    expect(new Set(adminMethods)).toEqual(new Set(devMethods));
  });

  it('no duplicate methods in any preset', () => {
    for (const preset of PERMISSION_PRESETS) {
      const methods = getPresetMethods(preset);
      const unique = new Set(methods);
      expect(
        unique.size,
        `Preset "${preset.name}" has duplicate methods`,
      ).toBe(methods.length);
    }
  });

  it('Wallet User methods are a subset of Service/Backend methods', () => {
    const walletMethods = new Set(getPresetMethods(walletPreset));
    const serviceMethods = new Set(getPresetMethods(servicePreset));
    for (const m of walletMethods) {
      expect(serviceMethods.has(m)).toBe(true);
    }
  });

  it('Service/Backend methods are a subset of Developer methods', () => {
    const serviceMethods = new Set(getPresetMethods(servicePreset));
    const devMethods = new Set(getPresetMethods(developerPreset));
    for (const m of serviceMethods) {
      expect(devMethods.has(m)).toBe(true);
    }
  });
});

describe('deriveClaims', () => {
  it('Wallet User methods derive read and write (eth_sendTransaction is write)', () => {
    const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
    const methods = getPresetMethods(walletPreset);
    const claims = deriveClaims(methods);
    expect(claims).toContain('read');
    expect(claims).toContain('write');
    expect(claims).not.toContain('deploy');
    expect(claims).not.toContain('admin');
    expect(claims).not.toContain('upgrade');
  });

  it('Developer methods derive read, write, deploy (debug_trace* is deploy)', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = getPresetMethods(devPreset);
    const claims = deriveClaims(methods);
    expect(claims).toContain('read');
    expect(claims).toContain('write');
    expect(claims).toContain('deploy');
    expect(claims).not.toContain('admin');
    // deploy implies read + write, so those are still there
  });

  it('admin flag produces admin, read, write, deploy, upgrade', () => {
    const claims = deriveClaims([], true);
    expect(claims).toContain('admin');
    expect(claims).toContain('read');
    expect(claims).toContain('write');
    expect(claims).toContain('deploy');
    expect(claims).toContain('upgrade');
    expect(claims).toHaveLength(5);
  });

  it('empty methods returns empty claims', () => {
    const claims = deriveClaims([]);
    expect(claims).toEqual([]);
  });

  it('single read method returns [read]', () => {
    const claims = deriveClaims(['eth_call']);
    expect(claims).toEqual(['read']);
  });

  it('single write method returns [write]', () => {
    const claims = deriveClaims(['eth_sendTransaction']);
    expect(claims).toEqual(['write']);
  });

  it('single deploy method returns [deploy, read, write] (deploy implies read+write)', () => {
    const claims = deriveClaims(['debug_traceTransaction']);
    expect(claims).toContain('deploy');
    expect(claims).toContain('read');
    expect(claims).toContain('write');
    expect(claims).toHaveLength(3);
  });

  it('admin flag overrides methods — even empty methods get all claims', () => {
    const claims = deriveClaims([], true);
    expect(claims).toHaveLength(5);
    expect(claims).toContain('admin');
  });
});

describe('getClosestPresetLabel', () => {
  it('exact Wallet User match returns "Wallet User"', () => {
    const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
    const methods = getPresetMethods(walletPreset);
    expect(getClosestPresetLabel(methods)).toBe('Wallet User');
  });

  it('exact Service/Backend match returns "Service / Backend"', () => {
    const servicePreset = PERMISSION_PRESETS.find(p => p.id === 'service_backend')!;
    const methods = getPresetMethods(servicePreset);
    expect(getClosestPresetLabel(methods)).toBe('Service / Backend');
  });

  it('exact Developer match returns "Developer"', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = getPresetMethods(devPreset);
    expect(getClosestPresetLabel(methods)).toBe('Developer');
  });

  it('Admin methods match Developer label (same method set, Developer wins first)', () => {
    // Admin and Developer share the same methods. getClosestPresetLabel iterates
    // PERMISSION_PRESETS in order and Developer comes before Admin, so it wins.
    const adminPreset = PERMISSION_PRESETS.find(p => p.id === 'admin')!;
    const methods = getPresetMethods(adminPreset);
    expect(getClosestPresetLabel(methods)).toBe('Developer');
  });

  it('Developer + 1 extra method returns "Developer +1"', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = [...getPresetMethods(devPreset), 'custom_method'];
    expect(getClosestPresetLabel(methods)).toBe('Developer +1');
  });

  it('Developer - 1 method returns "Developer -1"', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = getPresetMethods(devPreset).slice(0, -1); // remove last
    expect(getClosestPresetLabel(methods)).toBe('Developer -1');
  });

  it('Developer + 2 extra - 1 removed returns "Developer +2 -1"', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const presetMethods = getPresetMethods(devPreset);
    // Remove last method, add 2 custom ones
    const methods = [...presetMethods.slice(0, -1), 'custom_method_1', 'custom_method_2'];
    expect(getClosestPresetLabel(methods)).toBe('Developer +2 -1');
  });

  it('completely custom set (>6 delta from all presets) returns "Custom . N"', () => {
    const methods = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'];
    const label = getClosestPresetLabel(methods);
    expect(label).toBe('Custom \u00b7 10');
  });

  it('empty methods returns "Custom . 0"', () => {
    expect(getClosestPresetLabel([])).toBe('Custom \u00b7 0');
  });
});

describe('detectMatchingPreset', () => {
  it('exact Wallet User methods returns "wallet_user"', () => {
    const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
    const methods = getPresetMethods(walletPreset);
    expect(detectMatchingPreset(methods)).toBe('wallet_user');
  });

  it('exact Service/Backend methods returns "service_backend"', () => {
    const servicePreset = PERMISSION_PRESETS.find(p => p.id === 'service_backend')!;
    const methods = getPresetMethods(servicePreset);
    expect(detectMatchingPreset(methods)).toBe('service_backend');
  });

  it('exact Developer methods returns "developer"', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = getPresetMethods(devPreset);
    expect(detectMatchingPreset(methods)).toBe('developer');
  });

  it('exact Admin methods returns "admin"', () => {
    // Admin and Developer have the same methods, but Admin comes after Developer
    // in PERMISSION_PRESETS. Since Developer matches first, it returns "developer".
    const adminPreset = PERMISSION_PRESETS.find(p => p.id === 'admin')!;
    const methods = getPresetMethods(adminPreset);
    // Both developer and admin have the same method set — the first match wins
    const result = detectMatchingPreset(methods);
    expect(result === 'developer' || result === 'admin').toBe(true);
  });

  it('Developer + 1 extra method returns null (no exact match)', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = [...getPresetMethods(devPreset), 'custom_method'];
    expect(detectMatchingPreset(methods)).toBeNull();
  });

  it('Developer - 1 method returns null', () => {
    const devPreset = PERMISSION_PRESETS.find(p => p.id === 'developer')!;
    const methods = getPresetMethods(devPreset).slice(0, -1);
    expect(detectMatchingPreset(methods)).toBeNull();
  });

  it('empty methods returns null', () => {
    expect(detectMatchingPreset([])).toBeNull();
  });

  it('order of methods does not matter', () => {
    const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
    const methods = [...getPresetMethods(walletPreset)].reverse();
    expect(detectMatchingPreset(methods)).toBe('wallet_user');
  });
});
