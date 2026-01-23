import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthrimServer, createAuthrimServer } from '../../src/core/client.js';
import type { HttpProvider } from '../../src/providers/http.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';
import type { CacheProvider } from '../../src/providers/cache.js';
import type { CachedJwk } from '../../src/types/jwk.js';

describe('AuthrimServer', () => {
  let mockHttp: HttpProvider;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;
  let mockCache: CacheProvider<CachedJwk[]>;

  const nowSeconds = 1700000000;

  beforeEach(() => {
    mockHttp = {
      fetch: vi.fn(),
    };

    mockCrypto = {
      verifySignature: vi.fn().mockResolvedValue(true),
      importJwk: vi.fn().mockResolvedValue({} as CryptoKey),
      sha256: vi.fn().mockResolvedValue(new Uint8Array(32)),
      calculateThumbprint: vi.fn().mockResolvedValue('thumbprint'),
    };

    mockClock = {
      nowMs: () => nowSeconds * 1000,
      nowSeconds: () => nowSeconds,
    };

    mockCache = {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
    };
  });

  describe('constructor', () => {
    it('should create instance with minimal config', () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      expect(server).toBeInstanceOf(AuthrimServer);
    });

    it('should create instance with array issuers', () => {
      const server = new AuthrimServer({
        issuer: ['https://auth1.example.com', 'https://auth2.example.com'],
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      const config = server.getConfig();
      expect(config.issuer).toEqual(['https://auth1.example.com', 'https://auth2.example.com']);
    });

    it('should create instance with array audiences', () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: ['https://api1.example.com', 'https://api2.example.com'],
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      const config = server.getConfig();
      expect(config.audience).toEqual(['https://api1.example.com', 'https://api2.example.com']);
    });
  });

  describe('HTTPS validation', () => {
    it('should reject HTTP issuer when requireHttps is true', () => {
      expect(() => new AuthrimServer({
        issuer: 'http://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
        requireHttps: true,
      })).toThrow('must use HTTPS');
    });

    it('should reject HTTP jwksUri when requireHttps is true', () => {
      expect(() => new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'http://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
        requireHttps: true,
      })).toThrow('must use HTTPS');
    });

    it('should allow HTTP when requireHttps is false', () => {
      const server = new AuthrimServer({
        issuer: 'http://localhost:8080',
        audience: 'http://localhost:3000',
        jwksUri: 'http://localhost:8080/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
        requireHttps: false,
      });

      expect(server).toBeInstanceOf(AuthrimServer);
    });

    it('should reject invalid issuer URL', () => {
      expect(() => new AuthrimServer({
        issuer: 'not-a-valid-url',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      })).toThrow('Invalid issuer URL');
    });
  });

  describe('configuration defaults', () => {
    it('should use default clock tolerance of 60 seconds', () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      const config = server.getConfig();
      expect(config.clockToleranceSeconds).toBe(60);
    });

    it('should use default JWKS refresh interval of 1 hour', () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      const config = server.getConfig();
      expect(config.jwksRefreshIntervalMs).toBe(3600_000);
    });

    it('should override defaults with custom values', () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        clockToleranceSeconds: 120,
        jwksRefreshIntervalMs: 7200_000,
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      const config = server.getConfig();
      expect(config.clockToleranceSeconds).toBe(120);
      expect(config.jwksRefreshIntervalMs).toBe(7200_000);
    });
  });

  describe('init()', () => {
    it('should initialize with provided jwksUri', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      // Should not call fetch during init when jwksUri is provided
      expect(mockHttp.fetch).not.toHaveBeenCalled();
    });

    it('should discover jwksUri from OpenID configuration when not provided', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
        }),
      });

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/.well-known/openid-configuration',
        expect.objectContaining({
          headers: { Accept: 'application/json' },
        })
      );
    });

    it('should throw if OpenID configuration fetch fails', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        text: vi.fn().mockResolvedValue('Not Found'),
      });

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await expect(server.init()).rejects.toThrow('Failed to fetch OpenID Configuration');
    });

    it('should throw if OpenID configuration missing jwks_uri', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          issuer: 'https://auth.example.com',
          // jwks_uri missing
        }),
      });

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await expect(server.init()).rejects.toThrow('OpenID Configuration missing jwks_uri');
    });

    it('should be idempotent (multiple calls return same promise)', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      const promise1 = server.init();
      const promise2 = server.init();

      await Promise.all([promise1, promise2]);

      // Multiple init calls should only initialize once
      // The test verifies no errors occur with concurrent calls
    });

    it('should allow retry after init failure', async () => {
      let callCount = 0;
      mockHttp.fetch = vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({
            ok: false,
            status: 500,
            text: vi.fn().mockResolvedValue(''),
          });
        }
        return Promise.resolve({
          ok: true,
          json: vi.fn().mockResolvedValue({
            jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
          }),
        });
      });

      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      // First init should fail
      await expect(server.init()).rejects.toThrow();

      // Second init should succeed (retry)
      await server.init();
    });
  });

  describe('introspect()', () => {
    it('should throw if introspection endpoint not configured', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      await expect(server.introspect('test-token'))
        .rejects.toThrow('Introspection endpoint not configured');
    });

    it('should throw if client credentials not configured', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        introspectionEndpoint: 'https://auth.example.com/introspect',
        // No clientCredentials
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      await expect(server.introspect('test-token'))
        .rejects.toThrow('Introspection endpoint not configured');
    });

    it('should call introspection endpoint when configured', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ active: true, sub: 'user123' }),
      });

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

      const result = await server.introspect('test-token');
      expect(result.active).toBe(true);
      expect(result.sub).toBe('user123');
    });
  });

  describe('revoke()', () => {
    it('should throw if revocation endpoint not configured', async () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      await server.init();

      await expect(server.revoke('test-token'))
        .rejects.toThrow('Revocation endpoint not configured');
    });

    it('should call revocation endpoint when configured', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
      });

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

      await expect(server.revoke('test-token')).resolves.toBeUndefined();
    });
  });

  describe('invalidateJwksCache()', () => {
    it('should not throw before init', () => {
      const server = new AuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      // Should not throw even if not initialized
      expect(() => server.invalidateJwksCache()).not.toThrow();
    });
  });

  describe('createAuthrimServer()', () => {
    it('should create AuthrimServer instance', () => {
      const server = createAuthrimServer({
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
        jwksUri: 'https://auth.example.com/.well-known/jwks.json',
        http: mockHttp,
        crypto: mockCrypto,
        clock: mockClock,
      });

      expect(server).toBeInstanceOf(AuthrimServer);
    });
  });
});
