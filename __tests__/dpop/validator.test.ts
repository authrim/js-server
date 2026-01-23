import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DPoPValidator } from '../../src/dpop/validator.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { ClockProvider } from '../../src/providers/clock.js';

// Helper to create base64url encoded strings
function base64UrlEncode(input: string): string {
  return Buffer.from(input).toString('base64url');
}

// Helper to create a DPoP proof JWT string
function createDPoPProof(header: object, payload: object): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  return `${headerB64}.${payloadB64}.signature`;
}

describe('DPoPValidator', () => {
  let mockCrypto: CryptoProvider;
  let mockClock: ClockProvider;
  let validator: DPoPValidator;

  const validPublicJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'test-x',
    y: 'test-y',
  };

  const validHeader = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: validPublicJwk,
  };

  const nowSeconds = 1700000000;

  const validPayload = {
    jti: 'unique-id-123',
    htm: 'POST',
    htu: 'https://api.example.com/token',
    iat: nowSeconds,
  };

  beforeEach(() => {
    mockCrypto = {
      verifySignature: vi.fn().mockResolvedValue(true),
      importJwk: vi.fn().mockResolvedValue({} as CryptoKey),
      sha256: vi.fn().mockImplementation(async (data: Uint8Array) => {
        // Return a mock hash
        return new Uint8Array(32);
      }),
      calculateThumbprint: vi.fn().mockResolvedValue('mock-thumbprint'),
    };

    mockClock = {
      nowMs: () => nowSeconds * 1000,
      nowSeconds: () => nowSeconds,
    };

    validator = new DPoPValidator(mockCrypto, mockClock);
  });

  describe('header validation', () => {
    it('should reject invalid typ', async () => {
      const proof = createDPoPProof(
        { ...validHeader, typ: 'jwt' },
        validPayload
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('dpop+jwt');
    });

    it('should reject unsupported algorithm', async () => {
      const proof = createDPoPProof(
        { ...validHeader, alg: 'HS256' },
        validPayload
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('Unsupported algorithm');
    });

    it('should reject missing jwk', async () => {
      const proof = createDPoPProof(
        { typ: 'dpop+jwt', alg: 'ES256' },
        validPayload
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('Missing JWK');
    });
  });

  describe('private key rejection', () => {
    it('should reject JWK with d parameter (EC private key)', async () => {
      const proof = createDPoPProof(
        { ...validHeader, jwk: { ...validPublicJwk, d: 'private-key-value' } },
        validPayload
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('private key');
    });

    it('should reject JWK with RSA private parameters', async () => {
      const rsaJwk = {
        kty: 'RSA',
        n: 'modulus',
        e: 'AQAB',
        p: 'prime1', // Private parameter
      };

      const proof = createDPoPProof(
        { ...validHeader, alg: 'RS256', jwk: rsaJwk },
        validPayload
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('private key');
    });

    it('should reject JWK with q parameter', async () => {
      const rsaJwk = {
        kty: 'RSA',
        n: 'modulus',
        e: 'AQAB',
        q: 'prime2',
      };

      const proof = createDPoPProof(
        { ...validHeader, alg: 'RS256', jwk: rsaJwk },
        validPayload
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
    });

    it('should accept JWK without private parameters', async () => {
      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('payload validation', () => {
    it('should reject missing jti', async () => {
      const proof = createDPoPProof(
        validHeader,
        { htm: 'POST', htu: 'https://api.example.com/token', iat: nowSeconds }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('jti');
    });

    it('should reject missing htm', async () => {
      const proof = createDPoPProof(
        validHeader,
        { jti: 'id', htu: 'https://api.example.com/token', iat: nowSeconds }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('htm');
    });

    it('should reject missing htu', async () => {
      const proof = createDPoPProof(
        validHeader,
        { jti: 'id', htm: 'POST', iat: nowSeconds }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('htu');
    });

    it('should reject missing iat', async () => {
      const proof = createDPoPProof(
        validHeader,
        { jti: 'id', htm: 'POST', htu: 'https://api.example.com/token' }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
      expect(result.errorMessage).toContain('iat');
    });
  });

  describe('method validation', () => {
    it('should reject method mismatch', async () => {
      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'GET',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_method_mismatch');
    });

    it('should be case-insensitive for method', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, htm: 'post' }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('URI validation', () => {
    it('should reject URI mismatch', async () => {
      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/other',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_uri_mismatch');
    });

    it('should ignore query string in URI comparison', async () => {
      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token?foo=bar',
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('iat validation', () => {
    it('should reject expired proof', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, iat: nowSeconds - 200 }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        maxAge: 60,
        clockTolerance: 60,
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_iat_expired');
    });

    it('should reject future iat beyond tolerance', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, iat: nowSeconds + 200 }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        clockTolerance: 60,
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_iat_expired');
    });

    it('should accept iat within tolerance', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, iat: nowSeconds + 30 }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        clockTolerance: 60,
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('ath (access token hash) validation', () => {
    it('should require ath when accessToken is provided', async () => {
      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        accessToken: 'some-access-token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_ath_missing');
      expect(result.errorMessage).toContain('Missing ath claim');
    });

    it('should reject invalid ath', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, ath: 'invalid-hash' }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        accessToken: 'some-access-token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_ath_mismatch');
    });
  });

  describe('nonce validation', () => {
    it('should reject missing nonce when expected', async () => {
      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedNonce: 'expected-nonce',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_nonce_required');
    });

    it('should reject incorrect nonce', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, nonce: 'wrong-nonce' }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedNonce: 'expected-nonce',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_nonce_required');
    });

    it('should accept correct nonce', async () => {
      const proof = createDPoPProof(
        validHeader,
        { ...validPayload, nonce: 'expected-nonce' }
      );

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedNonce: 'expected-nonce',
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('thumbprint binding', () => {
    it('should reject mismatched thumbprint', async () => {
      // Mock a different thumbprint calculation
      mockCrypto.calculateThumbprint = vi.fn().mockResolvedValue('different-thumbprint');

      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
        expectedThumbprint: 'expected-thumbprint',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_binding_mismatch');
    });
  });

  describe('signature verification', () => {
    it('should reject invalid signature', async () => {
      mockCrypto.verifySignature = vi.fn().mockResolvedValue(false);

      const proof = createDPoPProof(validHeader, validPayload);

      const result = await validator.validate(proof, {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_signature_invalid');
    });
  });

  describe('proof format validation', () => {
    it('should reject malformed proof', async () => {
      const result = await validator.validate('not-a-jwt', {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
    });

    it('should reject proof with wrong number of parts', async () => {
      const result = await validator.validate('a.b', {
        method: 'POST',
        uri: 'https://api.example.com/token',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('dpop_proof_invalid');
    });
  });
});
