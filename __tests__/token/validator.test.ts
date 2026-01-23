import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TokenValidator } from '../../src/token/validator.js';
import type { JwksManager } from '../../src/jwks/manager.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';
import type { CachedJwk } from '../../src/types/jwk.js';

// Helper to create base64url encoded strings
function base64UrlEncode(input: string): string {
  return Buffer.from(input).toString('base64url');
}

// Helper to create a JWT string
function createJwt(header: object, payload: object): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  return `${headerB64}.${payloadB64}.signature`;
}

describe('TokenValidator', () => {
  let mockJwksManager: JwksManager;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;
  let validator: TokenValidator;

  const nowSeconds = 1700000000;

  const validHeader = {
    alg: 'RS256',
    typ: 'JWT',
    kid: 'key-1',
  };

  const validPayload = {
    iss: 'https://issuer.example.com',
    aud: 'https://api.example.com',
    sub: 'user123',
    exp: nowSeconds + 3600,
    iat: nowSeconds,
  };

  const mockCachedKey: CachedJwk = {
    jwk: {
      kty: 'RSA',
      n: 'modulus',
      e: 'AQAB',
      kid: 'key-1',
      alg: 'RS256',
    },
    cryptoKey: {} as CryptoKey,
  };

  beforeEach(() => {
    mockJwksManager = {
      getKey: vi.fn().mockResolvedValue({
        key: mockCachedKey,
        error: null,
        needsRefresh: false,
      }),
      invalidate: vi.fn(),
    } as unknown as JwksManager;

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

    validator = new TokenValidator({
      jwksManager: mockJwksManager,
      crypto: mockCrypto,
      clock: mockClock,
      options: {
        issuer: 'https://issuer.example.com',
        audience: 'https://api.example.com',
      },
    });
  });

  describe('successful validation', () => {
    it('should validate a valid token', async () => {
      const token = createJwt(validHeader, validPayload);

      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
      expect(result.error).toBeNull();
      expect(result.data?.claims.sub).toBe('user123');
      expect(result.data?.tokenType).toBe('Bearer');
    });

    it('should detect DPoP token by cnf.jkt claim', async () => {
      const dpopPayload = {
        ...validPayload,
        cnf: { jkt: 'thumbprint-hash' },
      };
      const token = createJwt(validHeader, dpopPayload);

      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
      expect(result.data?.tokenType).toBe('DPoP');
    });

    it('should calculate expiresIn correctly', async () => {
      const token = createJwt(validHeader, validPayload);

      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
      expect(result.data?.expiresIn).toBe(3600);
    });
  });

  describe('malformed token handling', () => {
    it('should reject malformed JWT', async () => {
      const result = await validator.validate('not-a-jwt');

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_malformed');
    });

    it('should reject JWT with wrong number of parts', async () => {
      const result = await validator.validate('header.payload');

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_malformed');
    });

    it('should reject JWT with invalid base64', async () => {
      const result = await validator.validate('!!!.@@@.###');

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_malformed');
    });
  });

  describe('JWKS key retrieval', () => {
    it('should handle JWKS key not found error', async () => {
      mockJwksManager.getKey = vi.fn().mockResolvedValue({
        key: null,
        error: { code: 'jwks_key_not_found', message: 'Key not found' },
        needsRefresh: false,
      });

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('jwks_key_not_found');
    });

    it('should handle JWKS ambiguous key error', async () => {
      mockJwksManager.getKey = vi.fn().mockResolvedValue({
        key: null,
        error: { code: 'jwks_key_ambiguous', message: 'Multiple matching keys' },
        needsRefresh: false,
      });

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('jwks_key_ambiguous');
    });

    it('should handle null key without error', async () => {
      mockJwksManager.getKey = vi.fn().mockResolvedValue({
        key: null,
        error: null,
        needsRefresh: false,
      });

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('jwks_key_not_found');
    });
  });

  describe('signature verification', () => {
    it('should reject invalid signature', async () => {
      mockCrypto.verifySignature = vi.fn().mockResolvedValue(false);

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('signature_invalid');
    });
  });

  describe('claims validation', () => {
    it('should reject wrong issuer', async () => {
      const payload = { ...validPayload, iss: 'https://wrong.example.com' };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_issuer');
    });

    it('should reject wrong audience', async () => {
      const payload = { ...validPayload, aud: 'https://wrong.example.com' };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_audience');
    });

    it('should reject expired token', async () => {
      const payload = { ...validPayload, exp: nowSeconds - 3600 };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_expired');
    });

    it('should accept token within clock tolerance', async () => {
      // Token expired 30 seconds ago, but tolerance is 60 seconds
      const payload = { ...validPayload, exp: nowSeconds - 30 };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
      expect(result.error).toBeNull();
    });
  });

  describe('scope validation', () => {
    beforeEach(() => {
      validator = new TokenValidator({
        jwksManager: mockJwksManager,
        crypto: mockCrypto,
        clock: mockClock,
        options: {
          issuer: 'https://issuer.example.com',
          audience: 'https://api.example.com',
          requiredScopes: ['read', 'write'],
        },
      });
    });

    it('should validate required scopes', async () => {
      const payload = { ...validPayload, scope: 'read write admin' };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
      expect(result.error).toBeNull();
    });

    it('should reject missing scopes', async () => {
      const payload = { ...validPayload, scope: 'read' };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('insufficient_scope');
      expect(result.error?.message).toContain('write');
    });

    it('should reject missing scope claim', async () => {
      const token = createJwt(validHeader, validPayload);

      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('insufficient_scope');
    });

    it('should reject empty scope claim', async () => {
      const payload = { ...validPayload, scope: '' };
      const token = createJwt(validHeader, payload);

      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('insufficient_scope');
    });
  });

  describe('error handling', () => {
    it('should handle AuthrimServerError', async () => {
      const { AuthrimServerError } = await import('../../src/types/errors.js');
      mockJwksManager.getKey = vi.fn().mockRejectedValue(
        new AuthrimServerError('jwks_fetch_error', 'JWKS fetch failed')
      );

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('jwks_fetch_error');
    });

    it('should handle generic errors', async () => {
      mockJwksManager.getKey = vi.fn().mockRejectedValue(new Error('Network error'));

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_token');
      expect(result.error?.message).toBe('Network error');
    });

    it('should handle non-Error throws', async () => {
      mockJwksManager.getKey = vi.fn().mockRejectedValue('string error');

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('invalid_token');
    });
  });

  describe('multiple issuers/audiences', () => {
    it('should validate against multiple issuers', async () => {
      validator = new TokenValidator({
        jwksManager: mockJwksManager,
        crypto: mockCrypto,
        clock: mockClock,
        options: {
          issuer: ['https://issuer1.example.com', 'https://issuer.example.com'],
          audience: 'https://api.example.com',
        },
      });

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
    });

    it('should validate against multiple audiences', async () => {
      validator = new TokenValidator({
        jwksManager: mockJwksManager,
        crypto: mockCrypto,
        clock: mockClock,
        options: {
          issuer: 'https://issuer.example.com',
          audience: ['https://api1.example.com', 'https://api.example.com'],
        },
      });

      const token = createJwt(validHeader, validPayload);
      const result = await validator.validate(token);

      expect(result.data).not.toBeNull();
    });
  });
});
