import { describe, it, expect, vi, beforeEach } from 'vitest';
import { JwksManager, type JwksManagerConfig } from '../../src/jwks/manager.js';
import type { HttpProvider } from '../../src/providers/http.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';
import type { CacheProvider } from '../../src/providers/cache.js';
import type { CachedJwk } from '../../src/types/jwk.js';

describe('JwksManager', () => {
  let mockHttp: HttpProvider;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;
  let mockCache: CacheProvider<CachedJwk[]>;
  let config: JwksManagerConfig;

  const validJwks = {
    keys: [
      {
        kty: 'RSA',
        n: 'modulus',
        e: 'AQAB',
        kid: 'key-1',
        alg: 'RS256',
        use: 'sig',
      },
    ],
  };

  beforeEach(() => {
    mockHttp = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        url: 'https://auth.example.com/.well-known/jwks.json',
        headers: new Map([['Cache-Control', 'max-age=3600']]),
        json: vi.fn().mockResolvedValue(validJwks),
      }),
    };

    mockCrypto = {
      verifySignature: vi.fn().mockResolvedValue(true),
      importJwk: vi.fn().mockResolvedValue({} as CryptoKey),
      sha256: vi.fn().mockResolvedValue(new Uint8Array(32)),
      calculateThumbprint: vi.fn().mockResolvedValue('thumbprint'),
    };

    mockClock = {
      nowMs: vi.fn().mockReturnValue(1700000000000),
      nowSeconds: vi.fn().mockReturnValue(1700000000),
    };

    mockCache = {
      get: vi.fn().mockReturnValue(undefined),
      set: vi.fn(),
      delete: vi.fn(),
    };

    config = {
      jwksUri: 'https://auth.example.com/.well-known/jwks.json',
      cacheTtlMs: 3600000,
      http: mockHttp,
      crypto: mockCrypto,
      clock: mockClock,
      cache: mockCache,
    };
  });

  describe('basic JWKS fetching', () => {
    it('should fetch and cache JWKS', async () => {
      const manager = new JwksManager(config);

      await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/.well-known/jwks.json',
        expect.any(Object)
      );
      expect(mockCache.set).toHaveBeenCalled();
    });

    it('should use cached keys when available', async () => {
      const cachedKeys: CachedJwk[] = [
        {
          jwk: validJwks.keys[0] as any,
          cryptoKey: {} as CryptoKey,
        },
      ];
      mockCache.get = vi.fn().mockReturnValue(cachedKeys);

      const manager = new JwksManager(config);
      await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      expect(mockHttp.fetch).not.toHaveBeenCalled();
    });

    it('should handle JWKS fetch error', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        url: config.jwksUri,
        headers: { get: () => null },
      });

      const manager = new JwksManager(config);

      await expect(manager.getKey({ alg: 'RS256', kid: 'key-1' })).rejects.toThrow('Failed to fetch JWKS');
    });

    it('should handle invalid JWKS response', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: config.jwksUri,
        headers: new Map(),
        json: vi.fn().mockResolvedValue({ invalid: 'structure' }),
      });

      const manager = new JwksManager(config);

      await expect(manager.getKey({ alg: 'RS256' })).rejects.toThrow('missing keys array');
    });
  });

  describe('cross-origin redirect protection', () => {
    it('should reject redirect to different host by default', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: 'https://evil.example.com/jwks.json', // Different host!
        headers: new Map(),
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const manager = new JwksManager(config);

      await expect(manager.getKey({ alg: 'RS256' })).rejects.toThrow(
        /redirected to a different host/
      );
    });

    it('should reject redirect to different subdomain', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: 'https://other.auth.example.com/.well-known/jwks.json',
        headers: new Map(),
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const manager = new JwksManager(config);

      await expect(manager.getKey({ alg: 'RS256' })).rejects.toThrow(
        /redirected to a different host/
      );
    });

    it('should allow same-host redirects', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: 'https://auth.example.com/v2/jwks.json', // Same host, different path
        headers: new Map(),
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const manager = new JwksManager(config);

      // Should not throw
      await expect(manager.getKey({ alg: 'RS256', kid: 'key-1' })).resolves.toBeDefined();
    });

    it('should allow cross-origin redirect when explicitly enabled', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: 'https://cdn.example.com/jwks.json', // Different host
        headers: new Map(),
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const managerWithRedirect = new JwksManager({
        ...config,
        allowCrossOriginRedirect: true,
      });

      // Should not throw because allowCrossOriginRedirect is true
      await expect(managerWithRedirect.getKey({ alg: 'RS256', kid: 'key-1' })).resolves.toBeDefined();
    });

    it('should handle response without url property', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        // url is undefined
        headers: new Map(),
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const manager = new JwksManager(config);

      // Should not throw, as we can't check redirect without url
      await expect(manager.getKey({ alg: 'RS256', kid: 'key-1' })).resolves.toBeDefined();
    });
  });

  describe('key import warnings', () => {
    it('should call onKeyImportWarning for unsupported key types', async () => {
      const onKeyImportWarning = vi.fn();
      const jwksWithUnsupportedKey = {
        keys: [
          { kty: 'oct', k: 'symmetric-key', kid: 'sym-1' }, // Symmetric key
          validJwks.keys[0],
        ],
      };

      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: config.jwksUri,
        headers: new Map(),
        json: vi.fn().mockResolvedValue(jwksWithUnsupportedKey),
      });

      const manager = new JwksManager({ ...config, onKeyImportWarning });

      await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      expect(onKeyImportWarning).toHaveBeenCalledWith(
        expect.objectContaining({
          kid: 'sym-1',
          kty: 'oct',
          reason: expect.any(String),
        })
      );
    });

    it('should call onKeyImportWarning for import failures', async () => {
      const onKeyImportWarning = vi.fn();
      mockCrypto.importJwk = vi.fn()
        .mockRejectedValueOnce(new Error('Import failed'))
        .mockResolvedValueOnce({} as CryptoKey);

      const jwksWithBadKey = {
        keys: [
          { kty: 'RSA', n: 'bad-modulus', e: 'AQAB', kid: 'bad-key', alg: 'RS256' },
          validJwks.keys[0],
        ],
      };

      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: config.jwksUri,
        headers: new Map(),
        json: vi.fn().mockResolvedValue(jwksWithBadKey),
      });

      const manager = new JwksManager({ ...config, onKeyImportWarning });

      await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      expect(onKeyImportWarning).toHaveBeenCalledWith(
        expect.objectContaining({
          kid: 'bad-key',
          reason: 'import_failed',
        })
      );
    });
  });

  describe('cache control parsing', () => {
    it('should use max-age from Cache-Control header', async () => {
      const headers = new Map([['Cache-Control', 'max-age=7200, public']]);
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: config.jwksUri,
        headers: { get: (name: string) => headers.get(name) ?? null },
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const manager = new JwksManager(config);
      await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      // Should use 7200 seconds = 7200000 ms from Cache-Control
      expect(mockCache.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Array),
        7200000
      );
    });

    it('should use default TTL when no Cache-Control', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        url: config.jwksUri,
        headers: { get: () => null },
        json: vi.fn().mockResolvedValue(validJwks),
      });

      const manager = new JwksManager(config);
      await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      expect(mockCache.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Array),
        3600000 // Default from config
      );
    });
  });

  describe('single-flight pattern', () => {
    it('should not make concurrent requests for same JWKS', async () => {
      let resolveFirst: (value: any) => void;
      const fetchPromise = new Promise((resolve) => {
        resolveFirst = resolve;
      });

      let fetchCount = 0;
      mockHttp.fetch = vi.fn().mockImplementation(async () => {
        fetchCount++;
        if (fetchCount === 1) {
          await fetchPromise;
        }
        return {
          ok: true,
          url: config.jwksUri,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue(validJwks),
        };
      });

      const manager = new JwksManager(config);

      // Start two concurrent requests
      const promise1 = manager.getKey({ alg: 'RS256', kid: 'key-1' });
      const promise2 = manager.getKey({ alg: 'RS256', kid: 'key-1' });

      // Resolve the first fetch
      resolveFirst!({
        ok: true,
        url: config.jwksUri,
        headers: { get: () => null },
        json: vi.fn().mockResolvedValue(validJwks),
      });

      await Promise.all([promise1, promise2]);

      // Should only make one fetch request
      expect(fetchCount).toBe(1);
    });
  });

  describe('key refresh on not found', () => {
    it('should refresh JWKS when key not found and needs refresh', async () => {
      // First call returns empty, second call returns key
      let callCount = 0;
      mockHttp.fetch = vi.fn().mockImplementation(async () => {
        callCount++;
        const keys = callCount === 1 ? [] : validJwks.keys;
        return {
          ok: true,
          url: config.jwksUri,
          headers: { get: () => null },
          json: vi.fn().mockResolvedValue({ keys }),
        };
      });

      const manager = new JwksManager(config);

      const result = await manager.getKey({ alg: 'RS256', kid: 'key-1' });

      // Should have fetched twice
      expect(callCount).toBe(2);
      expect(result.key).toBeDefined();
    });
  });

  describe('cache invalidation', () => {
    it('should invalidate cache when requested', () => {
      const manager = new JwksManager(config);

      manager.invalidate();

      expect(mockCache.delete).toHaveBeenCalledWith(
        expect.stringContaining('jwks:')
      );
    });
  });
});
