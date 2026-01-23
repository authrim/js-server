/**
 * Integration Test: Multi-Tenant Authentication Flow
 *
 * Tests authentication scenarios with multiple issuers and audiences:
 * - Multi-issuer configuration
 * - Multi-audience configuration
 * - Tenant isolation
 * - Cross-tenant rejection
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

// Helper to create a mock JWT
function createJwt(header: object, payload: object, signature = 'mock-signature'): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sigB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

describe('Integration: Multi-Tenant Authentication Flow', () => {
  const nowSeconds = 1700000000;
  let mockHttp: HttpProvider;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;

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

  beforeEach(() => {
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
  });

  describe('Scenario 1: Multiple Issuers (Federation)', () => {
    it('should accept tokens from any configured issuer', async () => {
      const server = new AuthrimServer({
        issuer: [
          'https://auth.company-a.com',
          'https://auth.company-b.com',
          'https://auth.company-c.com',
        ],
        audience: 'https://api.shared-platform.com',
        jwksUri: 'https://jwks.shared-platform.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token from Company A
      const tokenA = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.company-a.com',
          aud: 'https://api.shared-platform.com',
          sub: 'user-a-123',
          tenant: 'company-a',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const resultA = await server.validateToken(tokenA);
      expect(resultA.error).toBeNull();
      expect(resultA.data?.claims.sub).toBe('user-a-123');

      // Token from Company B
      const tokenB = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.company-b.com',
          aud: 'https://api.shared-platform.com',
          sub: 'user-b-456',
          tenant: 'company-b',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const resultB = await server.validateToken(tokenB);
      expect(resultB.error).toBeNull();
      expect(resultB.data?.claims.sub).toBe('user-b-456');

      // Token from Company C
      const tokenC = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.company-c.com',
          aud: 'https://api.shared-platform.com',
          sub: 'user-c-789',
          tenant: 'company-c',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const resultC = await server.validateToken(tokenC);
      expect(resultC.error).toBeNull();
      expect(resultC.data?.claims.sub).toBe('user-c-789');
    });

    it('should reject tokens from non-federated issuers', async () => {
      const server = new AuthrimServer({
        issuer: [
          'https://auth.company-a.com',
          'https://auth.company-b.com',
        ],
        audience: 'https://api.shared-platform.com',
        jwksUri: 'https://jwks.shared-platform.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token from unauthorized issuer
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.malicious-company.com',
          aud: 'https://api.shared-platform.com',
          sub: 'attacker',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);
      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_issuer');
    });
  });

  describe('Scenario 2: Multiple Audiences (Microservices)', () => {
    it('should accept tokens targeting any configured audience', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: [
          'https://api.users.example.com',
          'https://api.orders.example.com',
          'https://api.payments.example.com',
        ],
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token for Users API
      const usersToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.users.example.com',
          sub: 'user-123',
          scope: 'read:users',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const usersResult = await server.validateToken(usersToken);
      expect(usersResult.error).toBeNull();

      // Token for Orders API
      const ordersToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.orders.example.com',
          sub: 'user-123',
          scope: 'read:orders write:orders',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const ordersResult = await server.validateToken(ordersToken);
      expect(ordersResult.error).toBeNull();

      // Token with multiple audiences
      const multiAudToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: ['https://api.users.example.com', 'https://api.orders.example.com'],
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const multiResult = await server.validateToken(multiAudToken);
      expect(multiResult.error).toBeNull();
    });

    it('should reject tokens for non-configured audiences', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: ['https://api.users.example.com'],
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token for a different service
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.admin.example.com', // Not configured
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);
      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_audience');
    });
  });

  describe('Scenario 3: Tenant-Specific Validation', () => {
    it('should allow custom tenant validation via claims', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.saas-platform.com',
        audience: 'https://api.saas-platform.com',
        jwksUri: 'https://auth.saas-platform.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Token with tenant claim
      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.saas-platform.com',
          aud: 'https://api.saas-platform.com',
          sub: 'user-123',
          tenant_id: 'tenant-acme-corp',
          org_id: 'org-12345',
          roles: ['admin', 'user'],
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);
      expect(result.error).toBeNull();

      // Application can use tenant claims for authorization
      const claims = result.data?.claims;
      expect(claims?.tenant_id).toBe('tenant-acme-corp');
      expect(claims?.org_id).toBe('org-12345');
      expect(claims?.roles).toContain('admin');
    });
  });

  describe('Scenario 4: Environment Isolation', () => {
    it('should maintain separate configurations per environment', async () => {
      // Production server
      const prodServer = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        requireHttps: true,
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await prodServer.init();

      // Staging server (same code, different config)
      const stagingServer = new AuthrimServer({
        issuer: 'https://auth.staging.example.com',
        audience: 'https://api.staging.example.com',
        jwksUri: 'https://auth.staging.example.com/.well-known/jwks.json',
        requireHttps: true,
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await stagingServer.init();

      // Production token
      const prodToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'prod-user',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      // Staging token
      const stagingToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.staging.example.com',
          aud: 'https://api.staging.example.com',
          sub: 'staging-user',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      // Prod token works on prod server
      const prodResult = await prodServer.validateToken(prodToken);
      expect(prodResult.error).toBeNull();

      // Staging token works on staging server
      const stagingResult = await stagingServer.validateToken(stagingToken);
      expect(stagingResult.error).toBeNull();

      // Cross-environment should fail
      const crossResult1 = await prodServer.validateToken(stagingToken);
      expect(crossResult1.error?.code).toBe('invalid_issuer');

      const crossResult2 = await stagingServer.validateToken(prodToken);
      expect(crossResult2.error?.code).toBe('invalid_issuer');
    });
  });

  describe('Scenario 5: Regional Deployment', () => {
    it('should support regional issuers with shared audience', async () => {
      // API deployed in multiple regions, accepting tokens from regional IdPs
      const server = new AuthrimServer({
        issuer: [
          'https://auth.us-east.example.com',
          'https://auth.us-west.example.com',
          'https://auth.eu-west.example.com',
          'https://auth.ap-southeast.example.com',
        ],
        audience: 'https://api.global.example.com',
        jwksUri: 'https://jwks.global.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      const regions = [
        { issuer: 'https://auth.us-east.example.com', region: 'us-east' },
        { issuer: 'https://auth.us-west.example.com', region: 'us-west' },
        { issuer: 'https://auth.eu-west.example.com', region: 'eu-west' },
        { issuer: 'https://auth.ap-southeast.example.com', region: 'ap-southeast' },
      ];

      for (const { issuer, region } of regions) {
        const token = createJwt(
          { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
          {
            iss: issuer,
            aud: 'https://api.global.example.com',
            sub: `user-from-${region}`,
            region,
            exp: nowSeconds + 3600,
            iat: nowSeconds,
          }
        );

        const result = await server.validateToken(token);
        expect(result.error).toBeNull();
        expect(result.data?.claims.region).toBe(region);
      }
    });
  });

  describe('Scenario 6: B2B Partner Integration', () => {
    it('should support partner-specific token validation', async () => {
      // Platform accepting tokens from multiple B2B partners
      const server = new AuthrimServer({
        issuer: [
          'https://auth.platform.com',        // Own IdP
          'https://idp.partner-a.com',         // Partner A's IdP
          'https://login.partner-b.net',       // Partner B's IdP
        ],
        audience: 'https://api.platform.com',
        jwksUri: 'https://auth.platform.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Internal user
      const internalToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.platform.com',
          aud: 'https://api.platform.com',
          sub: 'internal-user@platform.com',
          user_type: 'internal',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const internalResult = await server.validateToken(internalToken);
      expect(internalResult.error).toBeNull();
      expect(internalResult.data?.claims.user_type).toBe('internal');

      // Partner A user
      const partnerAToken = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://idp.partner-a.com',
          aud: 'https://api.platform.com',
          sub: 'partner-user@partner-a.com',
          user_type: 'partner',
          partner_id: 'partner-a',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const partnerAResult = await server.validateToken(partnerAToken);
      expect(partnerAResult.error).toBeNull();
      expect(partnerAResult.data?.claims.partner_id).toBe('partner-a');
    });
  });

  describe('Scenario 7: Token Claims for Multi-Tenant Authorization', () => {
    it('should extract tenant information for authorization decisions', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.multi-tenant.com',
        audience: 'https://api.multi-tenant.com',
        jwksUri: 'https://auth.multi-tenant.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      const token = createJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'key-1' },
        {
          iss: 'https://auth.multi-tenant.com',
          aud: 'https://api.multi-tenant.com',
          sub: 'user-123',
          // Tenant context
          tenant_id: 'tenant-xyz',
          tenant_name: 'XYZ Corporation',
          tenant_plan: 'enterprise',
          // User permissions within tenant
          permissions: ['read:all', 'write:own', 'admin:users'],
          // Resource quotas
          quotas: {
            api_calls_per_day: 100000,
            storage_gb: 500,
          },
          exp: nowSeconds + 3600,
          iat: nowSeconds,
        }
      );

      const result = await server.validateToken(token);
      expect(result.error).toBeNull();

      const claims = result.data?.claims;

      // Authorization system can use these claims
      expect(claims?.tenant_id).toBe('tenant-xyz');
      expect(claims?.tenant_plan).toBe('enterprise');
      expect(claims?.permissions).toContain('admin:users');
      expect(claims?.quotas?.api_calls_per_day).toBe(100000);
    });
  });
});
