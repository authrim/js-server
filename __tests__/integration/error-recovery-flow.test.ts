/**
 * Integration Test: Error Recovery Flow
 *
 * Tests error handling and recovery scenarios including:
 * - JWKS cache refresh on key not found
 * - Network error recovery
 * - Graceful degradation
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthrimServer } from '../../src/core/client.js';
import type { HttpProvider } from '../../src/providers/http.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';

// Helper to create base64url encoded strings
function base64UrlEncode(input: string): string {
  return Buffer.from(input).toString('base64url');
}

// Helper to create a mock JWT string
function createMockJwt(header: object, payload: object, signature = 'mock-signature'): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sigB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

describe('Integration: Error Recovery Flow', () => {
  const nowSeconds = 1700000000;
  let mockHttp: HttpProvider;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;

  beforeEach(() => {
    mockClock = {
      nowMs: () => nowSeconds * 1000,
      nowSeconds: () => nowSeconds,
    };

    mockCrypto = {
      verifySignature: vi.fn().mockResolvedValue(true),
      importJwk: vi.fn().mockResolvedValue({} as CryptoKey),
      sha256: vi.fn().mockResolvedValue(new Uint8Array(32)),
      calculateThumbprint: vi.fn().mockResolvedValue('thumbprint-hash'),
    };
  });

  describe('Scenario 1: JWKS Key Rotation Recovery', () => {
    it('should refresh JWKS and find new key after rotation', async () => {
      const oldJwks = {
        keys: [
          { kty: 'RSA', n: 'old', e: 'AQAB', kid: 'old-key', alg: 'RS256', use: 'sig' },
        ],
      };

      const newJwks = {
        keys: [
          { kty: 'RSA', n: 'old', e: 'AQAB', kid: 'old-key', alg: 'RS256', use: 'sig' },
          { kty: 'RSA', n: 'new', e: 'AQAB', kid: 'new-key', alg: 'RS256', use: 'sig' },
        ],
      };

      let fetchCount = 0;
      mockHttp = {
        fetch: vi.fn().mockImplementation(() => {
          fetchCount++;
          // First call returns old JWKS, subsequent calls return new JWKS
          const jwks = fetchCount === 1 ? oldJwks : newJwks;
          return Promise.resolve({
            ok: true,
            headers: { get: () => null },
            json: vi.fn().mockResolvedValue(jwks),
          });
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // First validation with old key should succeed
      const tokenOld = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'old-key' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result1 = await server.validateToken(tokenOld);
      expect(result1.error).toBeNull();

      // Token with new key (not yet in cache)
      const tokenNew = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'new-key' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-456',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      // Should trigger JWKS refresh and succeed
      const result2 = await server.validateToken(tokenNew);

      expect(result2.error).toBeNull();
      expect(result2.data?.claims.sub).toBe('user-456');

      // Verify JWKS was fetched twice (initial + refresh)
      expect(mockHttp.fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Scenario 2: JWKS Fetch Failure', () => {
    it('should return error when JWKS cannot be fetched', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          text: vi.fn().mockResolvedValue('Server error'),
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.data).toBeNull();
      expect(result.error).not.toBeNull();
      // Should indicate JWKS fetch problem
      expect(result.error?.message).toContain('Failed to fetch JWKS');
    });

    it('should handle network timeout', async () => {
      mockHttp = {
        fetch: vi.fn().mockRejectedValue(new Error('Network timeout')),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.data).toBeNull();
      expect(result.error).not.toBeNull();
    });
  });

  describe('Scenario 3: OpenID Discovery Failure', () => {
    it('should fail initialization when discovery fails', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: false,
          status: 404,
          text: vi.fn().mockResolvedValue('Not Found'),
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        // No jwksUri - will try discovery
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await expect(server.init()).rejects.toThrow('Failed to fetch OpenID Configuration');
    });

    it('should recover when discovery succeeds on retry', async () => {
      let callCount = 0;
      mockHttp = {
        fetch: vi.fn().mockImplementation(() => {
          callCount++;
          if (callCount === 1) {
            // First call fails
            return Promise.resolve({
              ok: false,
              status: 503,
              text: vi.fn().mockResolvedValue('Service Unavailable'),
            });
          }
          // Second call succeeds
          return Promise.resolve({
            ok: true,
            json: vi.fn().mockResolvedValue({
              jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
            }),
          });
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      // First init fails
      await expect(server.init()).rejects.toThrow();

      // Second init succeeds
      await server.init();

      expect(mockHttp.fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Scenario 4: Introspection Error Recovery', () => {
    it('should throw meaningful error when introspection fails', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          text: vi.fn().mockResolvedValue('Invalid credentials'),
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        introspectionEndpoint: 'https://auth.example.com/introspect',
        clientCredentials: {
          clientId: 'my-client',
          clientSecret: 'my-secret',
        },
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      await expect(server.introspect('test-token')).rejects.toThrow(
        'Introspection request failed: 401 Unauthorized'
      );
    });
  });

  describe('Scenario 5: Revocation Error Handling', () => {
    it('should throw meaningful error when revocation fails', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          text: vi.fn().mockResolvedValue('Invalid token'),
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        revocationEndpoint: 'https://auth.example.com/revoke',
        clientCredentials: {
          clientId: 'my-client',
          clientSecret: 'my-secret',
        },
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      await expect(server.revoke('test-token')).rejects.toThrow(
        'Revocation request failed: 400 Bad Request'
      );
    });
  });

  describe('Scenario 6: Cache Invalidation', () => {
    it('should use fresh JWKS after cache invalidation', async () => {
      const jwks1 = {
        keys: [
          { kty: 'RSA', n: 'v1', e: 'AQAB', kid: 'key-v1', alg: 'RS256', use: 'sig' },
        ],
      };

      const jwks2 = {
        keys: [
          { kty: 'RSA', n: 'v2', e: 'AQAB', kid: 'key-v2', alg: 'RS256', use: 'sig' },
        ],
      };

      let fetchCount = 0;
      mockHttp = {
        fetch: vi.fn().mockImplementation(() => {
          fetchCount++;
          const jwks = fetchCount <= 2 ? jwks1 : jwks2;
          return Promise.resolve({
            ok: true,
            headers: { get: () => null },
            json: vi.fn().mockResolvedValue(jwks),
          });
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // First validation
      const token1 = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-v1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result1 = await server.validateToken(token1);
      expect(result1.error).toBeNull();

      // Invalidate cache
      server.invalidateJwksCache();

      // Try to validate with new key
      const token2 = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-v2' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-456',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result2 = await server.validateToken(token2);
      expect(result2.error).toBeNull();
      expect(result2.data?.claims.sub).toBe('user-456');
    });
  });

  describe('Scenario 7: Concurrent Initialization', () => {
    it('should handle concurrent init calls safely (discovery mode)', async () => {
      let fetchCount = 0;
      mockHttp = {
        fetch: vi.fn().mockImplementation(() => {
          fetchCount++;
          // Simulate slow network for discovery
          return new Promise((resolve) => {
            setTimeout(() => {
              resolve({
                ok: true,
                json: vi.fn().mockResolvedValue({
                  jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
                }),
              });
            }, 10);
          });
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        // No jwksUri - will trigger discovery
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      // Start multiple concurrent inits
      const promises = [
        server.init(),
        server.init(),
        server.init(),
      ];

      await Promise.all(promises);

      // Should only fetch once due to single-flight pattern
      // (all concurrent calls share the same promise)
      expect(fetchCount).toBe(1);
    });

    it('should not fetch when jwksUri is provided', async () => {
      mockHttp = {
        fetch: vi.fn(),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // When jwksUri is provided, no discovery fetch is needed
      expect(mockHttp.fetch).not.toHaveBeenCalled();
    });
  });
});
