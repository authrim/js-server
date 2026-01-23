import { describe, it, expect } from 'vitest';
import { validateClaims, getExpiresIn } from '../../src/token/validate-claims.js';
import type { StandardClaims } from '../../src/types/claims.js';

describe('validateClaims', () => {
  const defaultOptions = {
    issuer: 'https://issuer.example.com',
    audience: 'https://api.example.com',
    clockToleranceSeconds: 60,
    now: 1700000000, // Fixed timestamp for testing
  };

  describe('issuer validation', () => {
    it('should pass for matching issuer', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should pass for matching issuer in array', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer2.example.com',
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        issuer: ['https://issuer1.example.com', 'https://issuer2.example.com'],
      });
      expect(result.valid).toBe(true);
    });

    it('should fail for missing issuer', () => {
      const payload: StandardClaims = {
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_issuer');
    });

    it('should fail for wrong issuer', () => {
      const payload: StandardClaims = {
        iss: 'https://wrong-issuer.com',
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_issuer');
    });
  });

  describe('audience validation', () => {
    it('should pass for matching audience', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should pass for audience in array', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: ['https://other-api.com', 'https://api.example.com'],
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should pass when expected audience is array', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api2.example.com',
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        audience: ['https://api1.example.com', 'https://api2.example.com'],
      });
      expect(result.valid).toBe(true);
    });

    it('should fail for missing audience', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_audience');
    });

    it('should fail for wrong audience', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://wrong-api.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_audience');
    });
  });

  describe('expiration validation', () => {
    it('should pass for non-expired token', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1700001000, // 1000 seconds in the future
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should pass for token within tolerance', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1699999950, // 50 seconds in the past (within 60s tolerance)
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should fail for expired token', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1699999900, // 100 seconds in the past (beyond 60s tolerance)
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('token_expired');
    });

    it('should pass when no exp claim', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });
  });

  describe('not before validation', () => {
    it('should pass for token already valid', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        nbf: 1699999000, // In the past
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should pass for token within tolerance', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        nbf: 1700000050, // 50 seconds in the future (within 60s tolerance)
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should fail for token not yet valid', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        nbf: 1700000100, // 100 seconds in the future (beyond 60s tolerance)
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('token_not_yet_valid');
    });
  });

  describe('issued at validation', () => {
    it('should pass for token issued in the past', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: 1699999000,
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should pass for token within tolerance', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: 1700000050, // 50 seconds in the future (within 60s tolerance)
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(true);
    });

    it('should fail for token issued in the future', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: 1700000100, // 100 seconds in the future (beyond 60s tolerance)
      };

      const result = validateClaims(payload, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('iat_in_future');
    });
  });

  describe('OIDC ID Token validation (requireExp/requireIat)', () => {
    it('should fail when exp is missing and requireExp is true', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: 1700000000,
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        requireExp: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('missing_exp');
    });

    it('should pass when exp is present and requireExp is true', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1700001000,
        iat: 1700000000,
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        requireExp: true,
      });
      expect(result.valid).toBe(true);
    });

    it('should fail when iat is missing and requireIat is true', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1700001000,
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        requireIat: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('missing_iat');
    });

    it('should pass when iat is present and requireIat is true', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1700001000,
        iat: 1700000000,
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        requireIat: true,
      });
      expect(result.valid).toBe(true);
    });

    it('should validate full ID Token with both requireExp and requireIat', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: 1700001000,
        iat: 1700000000,
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        requireExp: true,
        requireIat: true,
      });
      expect(result.valid).toBe(true);
    });

    it('should fail ID Token validation when both exp and iat are missing', () => {
      const payload: StandardClaims = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
      };

      const result = validateClaims(payload, {
        ...defaultOptions,
        requireExp: true,
        requireIat: true,
      });
      expect(result.valid).toBe(false);
      // Should fail on exp first (checked before iat)
      expect(result.error?.code).toBe('missing_exp');
    });
  });
});

describe('numeric claims type validation', () => {
  const defaultOptions = {
    issuer: 'https://issuer.example.com',
    audience: 'https://api.example.com',
    clockToleranceSeconds: 60,
    now: 1700000000,
  };

  describe('exp type validation', () => {
    it('should reject string exp', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: '1700001000' as unknown as number,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_exp');
    });

    it('should reject null exp', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: null as unknown as number,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_exp');
    });

    it('should reject NaN exp', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: NaN,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_exp');
    });

    it('should reject Infinity exp', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        exp: Infinity,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_exp');
    });
  });

  describe('nbf type validation', () => {
    it('should reject string nbf', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        nbf: '1699999000' as unknown as number,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_nbf');
    });

    it('should reject null nbf', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        nbf: null as unknown as number,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_nbf');
    });

    it('should reject NaN nbf', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        nbf: NaN,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_nbf');
    });
  });

  describe('iat type validation', () => {
    it('should reject string iat', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: '1699999000' as unknown as number,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_iat');
    });

    it('should reject null iat', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: null as unknown as number,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_iat');
    });

    it('should reject NaN iat', () => {
      const payload = {
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
        iat: NaN,
      };

      const result = validateClaims(payload as StandardClaims, defaultOptions);
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('invalid_iat');
    });
  });
});

describe('getExpiresIn', () => {
  it('should return seconds until expiration', () => {
    const result = getExpiresIn(1700001000, 1700000000);
    expect(result).toBe(1000);
  });

  it('should return 0 for expired token', () => {
    const result = getExpiresIn(1699999000, 1700000000);
    expect(result).toBe(0);
  });

  it('should return undefined when no exp claim', () => {
    const result = getExpiresIn(undefined, 1700000000);
    expect(result).toBeUndefined();
  });
});
