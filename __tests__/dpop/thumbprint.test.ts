import { describe, it, expect, vi } from 'vitest';
import {
  calculateJwkThumbprint,
  verifyJwkThumbprint,
} from '../../src/dpop/thumbprint.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';

// Mock crypto provider
function createMockCryptoProvider(thumbprint: string): CryptoProvider {
  return {
    verifySignature: vi.fn(),
    importJwk: vi.fn(),
    sha256: vi.fn(),
    calculateThumbprint: vi.fn().mockResolvedValue(thumbprint),
  };
}

describe('calculateJwkThumbprint', () => {
  it('should delegate to crypto provider', async () => {
    const expectedThumbprint = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    const crypto = createMockCryptoProvider(expectedThumbprint);
    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: 'test-n',
      e: 'AQAB',
    };

    const result = await calculateJwkThumbprint(jwk, crypto);

    expect(result).toBe(expectedThumbprint);
    expect(crypto.calculateThumbprint).toHaveBeenCalledWith(jwk);
  });
});

describe('verifyJwkThumbprint', () => {
  it('should return true for matching thumbprint', async () => {
    const thumbprint = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    const crypto = createMockCryptoProvider(thumbprint);
    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: 'test-n',
      e: 'AQAB',
    };

    const result = await verifyJwkThumbprint(jwk, thumbprint, crypto);

    expect(result).toBe(true);
  });

  it('should return false for non-matching thumbprint', async () => {
    const actualThumbprint = 'actual-thumbprint';
    const crypto = createMockCryptoProvider(actualThumbprint);
    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: 'test-n',
      e: 'AQAB',
    };

    const result = await verifyJwkThumbprint(jwk, 'expected-thumbprint', crypto);

    expect(result).toBe(false);
  });
});
