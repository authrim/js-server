/**
 * Integration Test: Token Validation Flow
 *
 * Tests the complete flow from JWKS fetch to token validation,
 * verifying all components work together correctly.
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

describe('Integration: Token Validation Flow', () => {
  const nowSeconds = 1700000000;
  let mockHttp: HttpProvider;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;

  // Test JWKS
  const testJwks = {
    keys: [
      {
        kty: 'RSA',
        n: 'test-modulus',
        e: 'AQAB',
        kid: 'key-1',
        alg: 'RS256',
        use: 'sig',
      },
      {
        kty: 'RSA',
        n: 'test-modulus-2',
        e: 'AQAB',
        kid: 'key-2',
        alg: 'RS256',
        use: 'sig',
      },
    ],
  };

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

  describe('Scenario 1: Basic Token Validation', () => {
    it('should validate a token through complete flow: JWKS fetch → key selection → signature verification → claims validation', async () => {
      // Setup: HTTP returns JWKS
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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

      // Create valid token
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

      // Act
      const result = await server.validateToken(token);

      // Assert
      expect(result.error).toBeNull();
      expect(result.data).not.toBeNull();
      expect(result.data?.claims.sub).toBe('user-123');
      expect(result.data?.tokenType).toBe('Bearer');
      expect(result.data?.expiresIn).toBe(3600);

      // Verify JWKS was fetched
      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/.well-known/jwks.json',
        expect.any(Object)
      );

      // Verify signature was verified
      expect(mockCrypto.verifySignature).toHaveBeenCalled();
    });

    it('should identify DPoP token type when cnf.jkt claim is present', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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

      // Create DPoP-bound token
      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: 'dpop-key-thumbprint' },
        }
      );

      const result = await server.validateToken(token);

      expect(result.data?.tokenType).toBe('DPoP');
    });
  });

  describe('Scenario 2: Key Selection', () => {
    it('should select correct key by kid', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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

      // Token with key-2
      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-2' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-456',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.error).toBeNull();
      expect(result.data?.claims.sub).toBe('user-456');

      // Verify correct key was imported (key-2)
      expect(mockCrypto.importJwk).toHaveBeenCalledWith(
        expect.objectContaining({ kid: 'key-2' }),
        'RS256'
      );
    });

    it('should fail when kid not found in JWKS', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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

      // Token with unknown kid
      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'unknown-key' },
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
      expect(result.error?.code).toBe('jwks_key_not_found');
    });
  });

  describe('Scenario 3: Claims Validation', () => {
    it('should reject token with wrong issuer', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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
          iss: 'https://malicious.example.com', // Wrong issuer
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_issuer');
    });

    it('should reject token with wrong audience', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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
          aud: 'https://other-api.example.com', // Wrong audience
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_audience');
    });

    it('should reject expired token', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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
          exp: nowSeconds - 3600, // Expired 1 hour ago
          iat: nowSeconds - 7200,
        }
      );

      const result = await server.validateToken(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_expired');
    });

    it('should accept token within clock tolerance', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        clockToleranceSeconds: 120, // 2 minutes tolerance
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token expired 60 seconds ago, but within 120 second tolerance
      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds - 60,
          iat: nowSeconds - 3660,
        }
      );

      const result = await server.validateToken(token);

      expect(result.error).toBeNull();
      expect(result.data).not.toBeNull();
    });
  });

  describe('Scenario 4: Signature Verification', () => {
    it('should reject token with invalid signature', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
        }),
      };

      // Make signature verification fail
      mockCrypto.verifySignature = vi.fn().mockResolvedValue(false);

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
      expect(result.error?.code).toBe('signature_invalid');
    });
  });

  describe('Scenario 5: Multiple Issuers/Audiences', () => {
    it('should accept token from any configured issuer', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
        }),
      };

      const server = new AuthrimServer({
        issuer: ['https://auth1.example.com', 'https://auth2.example.com'],
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token from second issuer
      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth2.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.error).toBeNull();
      expect(result.data).not.toBeNull();
    });

    it('should accept token for any configured audience', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
        }),
      };

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: ['https://api1.example.com', 'https://api2.example.com'],
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token for second audience
      const token = createMockJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api2.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);

      expect(result.error).toBeNull();
      expect(result.data).not.toBeNull();
    });
  });

  describe('Scenario 6: Malformed Token Handling', () => {
    it('should reject completely malformed token', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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

      const result = await server.validateToken('not-a-jwt');

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_malformed');
    });

    it('should reject token with invalid base64', async () => {
      mockHttp = {
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(testJwks),
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

      const result = await server.validateToken('!!!.@@@.###');

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_malformed');
    });
  });
});
