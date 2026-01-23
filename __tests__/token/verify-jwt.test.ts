import { describe, it, expect } from 'vitest';
import { parseJwt, getSigningInput, getSignature, InsecureAlgorithmError } from '../../src/token/verify-jwt.js';

// Test JWT tokens (not cryptographically valid, just for structure testing)
const VALID_JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const INVALID_JWT_2_PARTS = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0';
const INVALID_JWT_4_PARTS = 'a.b.c.d';
const INVALID_JWT_MALFORMED_HEADER = 'invalid.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig';

describe('parseJwt', () => {
  describe('valid JWT', () => {
    it('should parse a valid JWT', () => {
      const result = parseJwt(VALID_JWT);

      expect(result.header).toEqual({
        alg: 'RS256',
        typ: 'JWT',
      });
      expect(result.payload).toEqual({
        sub: '1234567890',
        name: 'John Doe',
        iat: 1516239022,
      });
      expect(result.signature).toBe('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    });

    it('should parse JWT with kid in header', () => {
      // {"alg":"RS256","typ":"JWT","kid":"key-1"}
      const jwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig';
      const result = parseJwt(jwt);

      expect(result.header.kid).toBe('key-1');
    });

    it('should parse JWT with various algorithms', () => {
      // ES256
      const es256Header = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9';
      const jwt = `${es256Header}.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig`;
      const result = parseJwt(jwt);

      expect(result.header.alg).toBe('ES256');
    });
  });

  describe('invalid JWT', () => {
    it('should throw for JWT with 2 parts', () => {
      expect(() => parseJwt(INVALID_JWT_2_PARTS)).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw for JWT with 4 parts', () => {
      expect(() => parseJwt(INVALID_JWT_4_PARTS)).toThrow('Invalid JWT format: expected 3 parts');
    });

    it('should throw for empty string', () => {
      expect(() => parseJwt('')).toThrow('Invalid JWT format');
    });

    it('should throw for malformed header', () => {
      expect(() => parseJwt(INVALID_JWT_MALFORMED_HEADER)).toThrow();
    });

    it('should throw for non-JSON payload', () => {
      // Base64 of "not json"
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.bm90IGpzb24.sig';
      expect(() => parseJwt(jwt)).toThrow();
    });
  });

  describe('claims parsing', () => {
    it('should parse standard claims', () => {
      // {"iss":"https://issuer.example.com","sub":"user123","aud":"api","exp":1700000000,"nbf":1600000000,"iat":1600000000}
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InVzZXIxMjMiLCJhdWQiOiJhcGkiLCJleHAiOjE3MDAwMDAwMDAsIm5iZiI6MTYwMDAwMDAwMCwiaWF0IjoxNjAwMDAwMDAwfQ.sig';
      const result = parseJwt(jwt);

      expect(result.payload).toMatchObject({
        iss: 'https://issuer.example.com',
        sub: 'user123',
        aud: 'api',
        exp: 1700000000,
        nbf: 1600000000,
        iat: 1600000000,
      });
    });

    it('should parse array audience', () => {
      // {"aud":["api1","api2"]}
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiYXBpMSIsImFwaTIiXX0.sig';
      const result = parseJwt(jwt);

      expect(result.payload.aud).toEqual(['api1', 'api2']);
    });

    it('should parse DPoP confirmation claim', () => {
      // {"cnf":{"jkt":"thumbprint123"}}
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJjbmYiOnsiamt0IjoidGh1bWJwcmludDEyMyJ9fQ.sig';
      const result = parseJwt<{ cnf?: { jkt?: string } }>(jwt);

      expect(result.payload.cnf?.jkt).toBe('thumbprint123');
    });
  });
});

describe('getSigningInput', () => {
  it('should return header.payload as bytes', () => {
    const result = getSigningInput(VALID_JWT);
    const expected = new TextEncoder().encode(
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
    );

    expect(result).toEqual(expected);
  });
});

describe('getSignature', () => {
  it('should return signature as bytes', () => {
    const result = getSignature(VALID_JWT);

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
  });
});

describe('InsecureAlgorithmError', () => {
  // Helper to create a JWT with specific algorithm
  function createJwtWithAlg(alg: string): string {
    const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
    return `${header}.${payload}.signature`;
  }

  it('should throw InsecureAlgorithmError for alg: none', () => {
    const jwt = createJwtWithAlg('none');
    expect(() => parseJwt(jwt)).toThrow(InsecureAlgorithmError);
  });

  it('should throw InsecureAlgorithmError for alg: None (case variation)', () => {
    const jwt = createJwtWithAlg('None');
    expect(() => parseJwt(jwt)).toThrow(InsecureAlgorithmError);
  });

  it('should throw InsecureAlgorithmError for alg: NONE (uppercase)', () => {
    const jwt = createJwtWithAlg('NONE');
    expect(() => parseJwt(jwt)).toThrow(InsecureAlgorithmError);
  });

  it('should have correct error properties', () => {
    const jwt = createJwtWithAlg('none');
    try {
      parseJwt(jwt);
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(InsecureAlgorithmError);
      expect((error as InsecureAlgorithmError).code).toBe('insecure_algorithm');
      expect((error as InsecureAlgorithmError).name).toBe('InsecureAlgorithmError');
    }
  });
});

describe('JWT size limit', () => {
  it('should reject JWT exceeding 8KB', () => {
    // Create a JWT larger than 8192 bytes
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const largePayload = Buffer.from(JSON.stringify({ data: 'x'.repeat(10000) })).toString('base64url');
    const jwt = `${header}.${largePayload}.signature`;

    expect(jwt.length).toBeGreaterThan(8192);
    expect(() => parseJwt(jwt)).toThrow(/exceeds maximum size/);
  });

  it('should accept JWT within 8KB limit', () => {
    // Create a JWT within the limit
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
    const jwt = `${header}.${payload}.signature`;

    expect(jwt.length).toBeLessThan(8192);
    expect(() => parseJwt(jwt)).not.toThrow();
  });
});

describe('header validation', () => {
  it('should reject header without alg', () => {
    const header = Buffer.from(JSON.stringify({ typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
    const jwt = `${header}.${payload}.signature`;

    expect(() => parseJwt(jwt)).toThrow('Invalid JWT format');
  });

  it('should reject header with non-string alg', () => {
    const header = Buffer.from(JSON.stringify({ alg: 123 })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
    const jwt = `${header}.${payload}.signature`;

    expect(() => parseJwt(jwt)).toThrow('Invalid JWT format');
  });

  it('should reject header with null alg', () => {
    const header = Buffer.from(JSON.stringify({ alg: null })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64url');
    const jwt = `${header}.${payload}.signature`;

    expect(() => parseJwt(jwt)).toThrow('Invalid JWT format');
  });
});
