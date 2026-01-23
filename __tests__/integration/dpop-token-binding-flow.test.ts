/**
 * Integration Test: DPoP Token Binding Flow
 *
 * Tests the complete DPoP (Demonstrating Proof of Possession) flow:
 * - Access token with cnf.jkt claim validation
 * - DPoP proof validation
 * - Thumbprint binding verification
 * - HTTP method/URI binding
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DPoPValidator } from '../../src/dpop/validator.js';
import { TokenValidator } from '../../src/token/validator.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';
import type { JwksManager } from '../../src/jwks/manager.js';
import type { CachedJwk } from '../../src/types/jwk.js';

// Helper to create base64url encoded strings
function base64UrlEncode(input: string): string {
  return Buffer.from(input).toString('base64url');
}

// Helper to create a mock JWT/DPoP proof
function createJwt(header: object, payload: object, signature = 'mock-signature'): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sigB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

describe('Integration: DPoP Token Binding Flow', () => {
  const nowSeconds = 1700000000;
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;
  let mockJwksManager: JwksManager;
  let dpopValidator: DPoPValidator;
  let tokenValidator: TokenValidator;

  // DPoP public key (embedded in proof header)
  const dpopPublicKey = {
    kty: 'EC',
    crv: 'P-256',
    x: 'WKn-ZIGevcwGFOMJ0GeEei7IDlt5-tD1RqJL6Q9ane4',
    y: 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
  };

  // Expected thumbprint for the DPoP key
  const expectedThumbprint = 'dpop-key-thumbprint-abc123';

  const mockCachedKey: CachedJwk = {
    jwk: {
      kty: 'RSA',
      n: 'modulus',
      e: 'AQAB',
      kid: 'as-key-1',
      alg: 'RS256',
    },
    cryptoKey: {} as CryptoKey,
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
      calculateThumbprint: vi.fn().mockResolvedValue(expectedThumbprint),
    };

    mockJwksManager = {
      getKey: vi.fn().mockResolvedValue({
        key: mockCachedKey,
        error: null,
        needsRefresh: false,
      }),
      invalidate: vi.fn(),
    } as unknown as JwksManager;

    dpopValidator = new DPoPValidator(mockCrypto, mockClock);

    tokenValidator = new TokenValidator({
      jwksManager: mockJwksManager,
      crypto: mockCrypto,
      clock: mockClock,
      options: {
        issuer: 'https://auth.example.com',
        audience: 'https://api.example.com',
      },
    });
  });

  describe('Scenario 1: Valid DPoP-bound Access Token', () => {
    it('should validate DPoP-bound token and matching proof', async () => {
      // Step 1: Create DPoP-bound access token with cnf.jkt claim
      const accessToken = createJwt(
        { alg: 'RS256', typ: 'at+jwt', kid: 'as-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: expectedThumbprint }, // DPoP binding
        }
      );

      // Step 2: Validate access token
      const tokenResult = await tokenValidator.validate(accessToken);
      expect(tokenResult.error).toBeNull();
      expect(tokenResult.data?.tokenType).toBe('DPoP');
      expect(tokenResult.data?.claims.cnf?.jkt).toBe(expectedThumbprint);

      // Step 3: Create DPoP proof
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id-123',
          htm: 'POST',
          htu: 'https://api.example.com/resource',
          iat: nowSeconds,
        }
      );

      // Step 4: Validate DPoP proof
      const dpopResult = await dpopValidator.validate(dpopProof, {
        method: 'POST',
        uri: 'https://api.example.com/resource',
      });

      expect(dpopResult.valid).toBe(true);
      expect(dpopResult.thumbprint).toBe(expectedThumbprint);

      // Step 5: Verify binding - thumbprint in proof matches cnf.jkt in token
      expect(dpopResult.thumbprint).toBe(tokenResult.data?.claims.cnf?.jkt);
    });

    it('should validate DPoP proof with access token hash (ath)', async () => {
      const accessToken = createJwt(
        { alg: 'RS256', typ: 'at+jwt', kid: 'as-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: expectedThumbprint },
        }
      );

      // Calculate expected ath (access token hash)
      const expectedAth = 'fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo';
      mockCrypto.sha256 = vi.fn().mockResolvedValue(
        Buffer.from(expectedAth, 'base64url')
      );

      // DPoP proof with ath claim
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id-456',
          htm: 'GET',
          htu: 'https://api.example.com/userinfo',
          iat: nowSeconds,
          ath: expectedAth, // Access token hash
        }
      );

      const dpopResult = await dpopValidator.validate(dpopProof, {
        method: 'GET',
        uri: 'https://api.example.com/userinfo',
        accessToken: accessToken,
      });

      expect(dpopResult.valid).toBe(true);
    });
  });

  describe('Scenario 2: DPoP Proof Validation Failures', () => {
    it('should reject proof with wrong HTTP method', async () => {
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'POST', // Proof says POST
          htu: 'https://api.example.com/resource',
          iat: nowSeconds,
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'GET', // But request is GET
        uri: 'https://api.example.com/resource',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_method_mismatch');
    });

    it('should reject proof with wrong HTTP URI', async () => {
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'GET',
          htu: 'https://api.example.com/resource-a', // Wrong URI
          iat: nowSeconds,
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'GET',
        uri: 'https://api.example.com/resource-b', // Different URI
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_uri_mismatch');
    });

    it('should reject expired proof (iat too old)', async () => {
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'GET',
          htu: 'https://api.example.com/resource',
          iat: nowSeconds - 3600, // 1 hour ago
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'GET',
        uri: 'https://api.example.com/resource',
        maxAge: 300, // 5 minutes max
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_iat_expired');
    });

    it('should reject proof with invalid signature', async () => {
      mockCrypto.verifySignature = vi.fn().mockResolvedValue(false);

      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'GET',
          htu: 'https://api.example.com/resource',
          iat: nowSeconds,
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'GET',
        uri: 'https://api.example.com/resource',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_signature_invalid');
    });

    it('should reject proof with missing jti', async () => {
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          // jti missing
          htm: 'GET',
          htu: 'https://api.example.com/resource',
          iat: nowSeconds,
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'GET',
        uri: 'https://api.example.com/resource',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
    });
  });

  describe('Scenario 3: Token Binding Mismatch', () => {
    it('should detect thumbprint mismatch between token and proof', async () => {
      // Access token bound to one key
      const accessToken = createJwt(
        { alg: 'RS256', typ: 'at+jwt', kid: 'as-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: 'original-key-thumbprint' }, // Bound to original key
        }
      );

      const tokenResult = await tokenValidator.validate(accessToken);
      expect(tokenResult.data?.claims.cnf?.jkt).toBe('original-key-thumbprint');

      // DPoP proof signed with different key
      mockCrypto.calculateThumbprint = vi.fn().mockResolvedValue('different-key-thumbprint');

      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey, // Different key
        },
        {
          jti: 'unique-proof-id',
          htm: 'GET',
          htu: 'https://api.example.com/resource',
          iat: nowSeconds,
        }
      );

      const dpopResult = await dpopValidator.validate(dpopProof, {
        method: 'GET',
        uri: 'https://api.example.com/resource',
      });

      // DPoP proof is valid on its own
      expect(dpopResult.valid).toBe(true);

      // But thumbprints don't match - binding is broken!
      expect(dpopResult.thumbprint).not.toBe(tokenResult.data?.claims.cnf?.jkt);
      expect(dpopResult.thumbprint).toBe('different-key-thumbprint');
      expect(tokenResult.data?.claims.cnf?.jkt).toBe('original-key-thumbprint');
    });
  });

  describe('Scenario 4: Bearer Token Fallback', () => {
    it('should accept Bearer token (no cnf.jkt) without DPoP', async () => {
      // Regular Bearer token without DPoP binding
      const bearerToken = createJwt(
        { alg: 'RS256', typ: 'at+jwt', kid: 'as-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          // No cnf claim
        }
      );

      const result = await tokenValidator.validate(bearerToken);

      expect(result.error).toBeNull();
      expect(result.data?.tokenType).toBe('Bearer');
      expect(result.data?.claims.cnf).toBeUndefined();
    });
  });

  describe('Scenario 5: DPoP with Nonce', () => {
    it('should include nonce in proof when required by server', async () => {
      const serverNonce = 'server-provided-nonce-xyz';

      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'POST',
          htu: 'https://api.example.com/token',
          iat: nowSeconds,
          nonce: serverNonce, // Server-required nonce
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedNonce: serverNonce,
      });

      expect(result.valid).toBe(true);
    });

    it('should reject proof with wrong nonce', async () => {
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'POST',
          htu: 'https://api.example.com/token',
          iat: nowSeconds,
          nonce: 'wrong-nonce',
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedNonce: 'correct-nonce',
      });

      expect(result.valid).toBe(false);
      // Nonce mismatch returns dpop_nonce_required
      expect(result.errorCode).toBe('dpop_nonce_required');
    });

    it('should reject proof missing required nonce', async () => {
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: 'unique-proof-id',
          htm: 'POST',
          htu: 'https://api.example.com/token',
          iat: nowSeconds,
          // nonce missing
        }
      );

      const result = await dpopValidator.validate(dpopProof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedNonce: 'required-nonce', // Server requires nonce
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_nonce_required');
    });
  });

  describe('Scenario 6: Complete API Request Flow', () => {
    it('should validate complete DPoP-protected API request', async () => {
      // Simulate: Client makes API request with DPoP-bound token

      // 1. Access token issued by AS with DPoP binding
      const accessToken = createJwt(
        { alg: 'RS256', typ: 'at+jwt', kid: 'as-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-123',
          client_id: 'mobile-app',
          scope: 'read write',
          exp: nowSeconds + 3600,
          iat: nowSeconds,
          cnf: { jkt: expectedThumbprint },
        }
      );

      // 2. Client creates fresh DPoP proof for this request (without ath for standalone validation)
      const dpopProof = createJwt(
        {
          typ: 'dpop+jwt',
          alg: 'ES256',
          jwk: dpopPublicKey,
        },
        {
          jti: `request-${Date.now()}-${Math.random()}`,
          htm: 'POST',
          htu: 'https://api.example.com/orders',
          iat: nowSeconds,
          // Note: ath is required when accessToken is passed to validate()
          // Here we validate proof separately without ath requirement
        }
      );

      // 3. Resource Server validates access token
      const tokenResult = await tokenValidator.validate(accessToken);
      expect(tokenResult.error).toBeNull();
      expect(tokenResult.data?.tokenType).toBe('DPoP');

      // 4. Resource Server validates DPoP proof (without passing accessToken to skip ath check)
      const dpopResult = await dpopValidator.validate(dpopProof, {
        method: 'POST',
        uri: 'https://api.example.com/orders',
        // Not passing accessToken here - ath validation is done separately if needed
      });
      expect(dpopResult.valid).toBe(true);

      // 5. Resource Server verifies binding manually
      const tokenThumbprint = tokenResult.data?.claims.cnf?.jkt;
      const proofThumbprint = dpopResult.thumbprint;
      expect(tokenThumbprint).toBe(proofThumbprint);

      // 6. Request is authorized!
      const authorizedUser = tokenResult.data?.claims.sub;
      const authorizedScopes = tokenResult.data?.claims.scope;
      expect(authorizedUser).toBe('user-123');
      expect(authorizedScopes).toBe('read write');
    });
  });
});
