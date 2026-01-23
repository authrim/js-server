import { describe, it, expect } from 'vitest';
import {
  selectKey,
  selectKeyByKid,
  selectKeyByAlgorithm,
} from '../../src/jwks/key-selector.js';
import type { CachedJwk, PublicJwk } from '../../src/types/jwk.js';
import type { JwtHeader } from '../../src/types/claims.js';

// Helper to create mock CachedJwk
function createMockKey(overrides: Partial<PublicJwk> = {}): CachedJwk {
  const jwk: PublicJwk = {
    kty: 'RSA',
    n: 'mock-n',
    e: 'AQAB',
    ...overrides,
  } as PublicJwk;

  return {
    jwk,
    cryptoKey: {} as CryptoKey, // Mock CryptoKey
  };
}

describe('selectKeyByKid', () => {
  it('should find key by kid', () => {
    const keys: CachedJwk[] = [
      createMockKey({ kid: 'key-1', alg: 'RS256' }),
      createMockKey({ kid: 'key-2', alg: 'RS256' }),
    ];

    const result = selectKeyByKid(keys, 'key-2', 'RS256');

    expect(result.key).toBe(keys[1]);
    expect(result.error).toBeNull();
    expect(result.needsRefresh).toBe(false);
  });

  it('should filter by use=sig', () => {
    const keys: CachedJwk[] = [
      createMockKey({ kid: 'key-1', use: 'enc' }),
      createMockKey({ kid: 'key-1', use: 'sig' }),
    ];

    const result = selectKeyByKid(keys, 'key-1', 'RS256');

    expect(result.key).toBe(keys[1]);
  });

  it('should accept key without use property', () => {
    const keys: CachedJwk[] = [createMockKey({ kid: 'key-1' })]; // No use property

    const result = selectKeyByKid(keys, 'key-1', 'RS256');

    expect(result.key).toBe(keys[0]);
  });

  it('should filter by algorithm match', () => {
    const keys: CachedJwk[] = [
      createMockKey({ kid: 'key-1', alg: 'RS384' }),
      createMockKey({ kid: 'key-1', alg: 'RS256' }),
    ];

    const result = selectKeyByKid(keys, 'key-1', 'RS256');

    expect(result.key).toBe(keys[1]);
  });

  it('should return error and needsRefresh when key not found', () => {
    const keys: CachedJwk[] = [createMockKey({ kid: 'key-1' })];

    const result = selectKeyByKid(keys, 'key-2', 'RS256');

    expect(result.key).toBeNull();
    expect(result.error?.code).toBe('jwks_key_not_found');
    expect(result.needsRefresh).toBe(true);
  });
});

describe('selectKeyByAlgorithm', () => {
  it('should find single matching key', () => {
    const keys: CachedJwk[] = [
      createMockKey({ alg: 'RS256' }),
      createMockKey({ alg: 'ES256' }),
    ];

    const result = selectKeyByAlgorithm(keys, 'ES256');

    expect(result.key).toBe(keys[1]);
    expect(result.error).toBeNull();
  });

  it('should find key without explicit alg', () => {
    const keys: CachedJwk[] = [createMockKey({})]; // No alg, should match any

    const result = selectKeyByAlgorithm(keys, 'RS256');

    expect(result.key).toBe(keys[0]);
  });

  it('should return ambiguous error when no keys match', () => {
    const keys: CachedJwk[] = [createMockKey({ alg: 'RS384' })];

    const result = selectKeyByAlgorithm(keys, 'RS256');

    expect(result.key).toBeNull();
    expect(result.error?.code).toBe('jwks_key_ambiguous');
    expect(result.needsRefresh).toBe(false);
  });

  it('should return ambiguous error when multiple keys match', () => {
    const keys: CachedJwk[] = [
      createMockKey({ alg: 'RS256' }),
      createMockKey({ alg: 'RS256' }),
    ];

    const result = selectKeyByAlgorithm(keys, 'RS256');

    expect(result.key).toBeNull();
    expect(result.error?.code).toBe('jwks_key_ambiguous');
    expect(result.error?.message).toContain('Multiple keys');
  });

  it('should filter out encryption keys', () => {
    const keys: CachedJwk[] = [
      createMockKey({ alg: 'RS256', use: 'enc' }),
      createMockKey({ alg: 'RS256', use: 'sig' }),
    ];

    const result = selectKeyByAlgorithm(keys, 'RS256');

    expect(result.key).toBe(keys[1]);
  });
});

describe('selectKey', () => {
  it('should use kid selection when kid is present', () => {
    const keys: CachedJwk[] = [
      createMockKey({ kid: 'key-1', alg: 'RS256' }),
      createMockKey({ kid: 'key-2', alg: 'RS256' }),
    ];
    const header: JwtHeader = { alg: 'RS256', kid: 'key-2' };

    const result = selectKey(keys, header);

    expect(result.key).toBe(keys[1]);
  });

  it('should use algorithm selection when kid is absent', () => {
    const keys: CachedJwk[] = [
      createMockKey({ alg: 'RS256' }),
      createMockKey({ alg: 'ES256' }),
    ];
    const header: JwtHeader = { alg: 'ES256' };

    const result = selectKey(keys, header);

    expect(result.key).toBe(keys[1]);
  });

  it('should prioritize kid over algorithm', () => {
    const keys: CachedJwk[] = [
      createMockKey({ kid: 'key-1', alg: 'RS256' }),
      createMockKey({ kid: 'key-2', alg: 'ES256' }),
    ];
    // Header has kid that matches RS256 key, but alg says ES256
    const header: JwtHeader = { alg: 'ES256', kid: 'key-1' };

    const result = selectKey(keys, header);

    // Should not find because kid=key-1 has alg=RS256, not ES256
    expect(result.error?.code).toBe('jwks_key_not_found');
  });
});
