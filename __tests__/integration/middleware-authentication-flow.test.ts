/**
 * Integration Test: Middleware Authentication Flow
 *
 * Tests the complete authentication flow through the middleware layer:
 * - HTTP request header extraction
 * - Bearer token validation
 * - DPoP token validation
 * - Error response generation
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { authenticateRequest } from '../../src/middleware/authenticate.js';
import { AuthrimServer } from '../../src/core/client.js';
import type { HttpProvider } from '../../src/providers/http.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';

// Helper to create base64url encoded strings
function base64UrlEncode(input: string): string {
  return Buffer.from(input).toString('base64url');
}

// Helper to create a mock JWT
function createJwt(header: object, payload: object, signature = 'mock-signature'): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sigB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

describe('Integration: Middleware Authentication Flow', () => {
  const nowSeconds = 1700000000;
  let mockHttp: HttpProvider;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;
  let server: AuthrimServer;

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
    ],
  };

  beforeEach(async () => {
    mockClock = {
      nowMs: () => nowSeconds * 1000,
      nowSeconds: () => nowSeconds,
    };

    mockCrypto = {
      verifySignature: vi.fn().mockResolvedValue(true),
      importJwk: vi.fn().mockResolvedValue({} as CryptoKey),
      sha256: vi.fn().mockResolvedValue(new Uint8Array(32)),
      calculateThumbprint: vi.fn().mockResolvedValue('thumbprint'),
    };

    mockHttp = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        headers: { get: () => null },
        json: vi.fn().mockResolvedValue(testJwks),
      }),
    };

    server = new AuthrimServer({
      issuer: 'https://auth.example.com',
      audience: 'https://api.example.com',
      jwksUri: 'https://auth.example.com/.well-known/jwks.json',
      http: mockHttp,
      crypto: mockCrypto,
      clock: mockClock,
    });

    await server.init();
  });

  describe('Scenario 1: Bearer Token Authentication', () => {
    it('should authenticate valid Bearer token', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await authenticateRequest(server, {
        headers: {
          authorization: `Bearer ${token}`,
        },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.sub).toBe('user-123');
      expect(result.data?.tokenType).toBe('Bearer');
    });

    it('should handle case-insensitive Authorization header', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      // Various header casing
      const testCases = [
        { authorization: `Bearer ${token}` },
        { Authorization: `Bearer ${token}` },
        { AUTHORIZATION: `Bearer ${token}` },
      ];

      for (const headers of testCases) {
        const result = await authenticateRequest(server, {
          headers,
          method: 'GET',
          url: 'https://api.example.com/users',
        });

        expect(result.error).toBeNull();
        expect(result.data?.claims.claims.sub).toBe('user-123');
      }
    });
  });

  describe('Scenario 2: Missing/Invalid Authorization Header', () => {
    it('should reject request without Authorization header', async () => {
      const result = await authenticateRequest(server, {
        headers: {},
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error).not.toBeNull();
      expect(result.error?.code).toBe('invalid_token');
    });

    it('should reject request with empty Authorization header', async () => {
      const result = await authenticateRequest(server, {
        headers: { authorization: '' },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_token');
    });

    it('should reject unsupported auth scheme', async () => {
      const result = await authenticateRequest(server, {
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_token');
    });

    it('should reject malformed Bearer token', async () => {
      const result = await authenticateRequest(server, {
        headers: { authorization: 'Bearer not-a-valid-jwt' },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_malformed');
    });
  });

  describe('Scenario 3: Token Validation Failures', () => {
    it('should reject expired token', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds - 3600, // Expired
          iat: nowSeconds - 7200,
        }
      );

      const result = await authenticateRequest(server, {
        headers: { authorization: `Bearer ${token}` },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_expired');
    });

    it('should reject token with wrong issuer', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://malicious.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await authenticateRequest(server, {
        headers: { authorization: `Bearer ${token}` },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_issuer');
    });

    it('should reject token with invalid signature', async () => {
      mockCrypto.verifySignature = vi.fn().mockResolvedValue(false);

      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await authenticateRequest(server, {
        headers: { authorization: `Bearer ${token}` },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('signature_invalid');
    });
  });

  describe('Scenario 4: DPoP Authentication', () => {
    const dpopPublicKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'test-x',
      y: 'test-y',
    };

    it('should authenticate valid DPoP token with proof', async () => {
      const thumbprint = 'dpop-thumbprint-123';
      mockCrypto.calculateThumbprint = vi.fn().mockResolvedValue(thumbprint);

      // DPoP-bound access token
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: thumbprint },
        }
      );

      // Mock sha256 to return a predictable hash for ath
      const mockAth = base64UrlEncode('mock-ath-hash');
      mockCrypto.sha256 = vi.fn().mockResolvedValue(Buffer.from('mock-ath-hash'));

      // DPoP proof with ath claim
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'POST',
          htu: 'https://api.example.com/orders',
          iat: nowSeconds,
          ath: mockAth, // Access token hash required when using with access token
        }
      );

      const result = await authenticateRequest(server, {
        headers: {
          authorization: `DPoP ${token}`,
          dpop: dpopProof,
        },
        method: 'POST',
        url: 'https://api.example.com/orders',
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.sub).toBe('user-123');
      expect(result.data?.tokenType).toBe('DPoP');
    });

    it('should reject DPoP token without proof', async () => {
      const thumbprint = 'dpop-thumbprint-123';

      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: thumbprint },
        }
      );

      const result = await authenticateRequest(server, {
        headers: {
          authorization: `DPoP ${token}`,
          // Missing dpop proof header
        },
        method: 'POST',
        url: 'https://api.example.com/orders',
      });

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('dpop_proof_missing');
    });
  });

  describe('Scenario 5: Real-World HTTP Requests', () => {
    it('should handle typical REST API GET request', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          scope: 'read:users',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await authenticateRequest(server, {
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'accept': 'application/json',
        },
        method: 'GET',
        url: 'https://api.example.com/users/123',
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.sub).toBe('user-123');
      expect(result.data?.claims.claims.scope).toBe('read:users');
    });

    it('should handle typical REST API POST request', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          scope: 'write:orders',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await authenticateRequest(server, {
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'content-length': '256',
        },
        method: 'POST',
        url: 'https://api.example.com/orders',
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.scope).toBe('write:orders');
    });

    it('should handle request with query parameters', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await authenticateRequest(server, {
        headers: { authorization: `Bearer ${token}` },
        method: 'GET',
        url: 'https://api.example.com/users?page=1&limit=10&sort=name',
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.sub).toBe('user-123');
    });
  });

  describe('Scenario 6: Framework Adapter Simulation', () => {
    it('should work with Express-style request object', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      // Simulate Express request object transformation
      const expressReq = {
        headers: { authorization: `Bearer ${token}` },
        method: 'GET',
        protocol: 'https',
        get: (name: string) => name === 'host' ? 'api.example.com' : undefined,
        originalUrl: '/users/123',
      };

      const result = await authenticateRequest(server, {
        headers: expressReq.headers,
        method: expressReq.method,
        url: `${expressReq.protocol}://${expressReq.get('host')}${expressReq.originalUrl}`,
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.sub).toBe('user-123');
    });

    it('should work with multiple header values (array)', async () => {
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      // Some frameworks provide headers as arrays
      const result = await authenticateRequest(server, {
        headers: {
          authorization: [`Bearer ${token}`], // Array format
          'x-custom-header': ['value1', 'value2'],
        },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.error).toBeNull();
      expect(result.data?.claims.claims.sub).toBe('user-123');
    });
  });

  describe('Scenario 7: Error Response Information', () => {
    it('should provide error for missing token', async () => {
      const result = await authenticateRequest(server, {
        headers: {},
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.error?.code).toBe('invalid_token');
      expect(result.error?.httpStatus).toBe(401);
      // Application should return 401 with WWW-Authenticate: Bearer
    });

    it('should provide error details for invalid token', async () => {
      const result = await authenticateRequest(server, {
        headers: { authorization: 'Bearer malformed' },
        method: 'GET',
        url: 'https://api.example.com/users',
      });

      expect(result.error).not.toBeNull();
      expect(result.error?.code).toBeDefined();
      expect(result.error?.message).toBeDefined();
    });
  });
});
