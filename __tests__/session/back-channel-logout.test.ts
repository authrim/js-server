import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  BackChannelLogoutValidator,
  BACKCHANNEL_LOGOUT_EVENT,
} from '../../src/session/back-channel-logout.js';
import { base64UrlEncodeString } from '../../src/utils/base64url.js';

/**
 * Helper to create a mock JWT for testing
 */
function createMockJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>
): string {
  const headerB64 = base64UrlEncodeString(JSON.stringify(header));
  const payloadB64 = base64UrlEncodeString(JSON.stringify(payload));
  const signature = 'mock-signature';
  return `${headerB64}.${payloadB64}.${signature}`;
}

describe('BackChannelLogoutValidator', () => {
  let validator: BackChannelLogoutValidator;
  const defaultIssuer = 'https://op.example.com';
  const defaultAudience = 'my-client-id';
  const defaultHeader = { alg: 'RS256', typ: 'JWT' };

  // Use a fixed timestamp for testing
  const mockNow = 1700000000;

  beforeEach(() => {
    validator = new BackChannelLogoutValidator();
    vi.useFakeTimers();
    vi.setSystemTime(mockNow * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function createValidLogoutTokenPayload(): Record<string, unknown> {
    return {
      iss: defaultIssuer,
      aud: defaultAudience,
      iat: mockNow,
      exp: mockNow + 300, // expires in 5 minutes
      jti: 'unique-jti-123',
      sub: 'user-123',
      events: {
        [BACKCHANNEL_LOGOUT_EVENT]: {},
      },
    };
  }

  describe('BACKCHANNEL_LOGOUT_EVENT constant', () => {
    it('should have correct value', () => {
      expect(BACKCHANNEL_LOGOUT_EVENT).toBe('http://schemas.openid.net/event/backchannel-logout');
    });
  });

  describe('validate', () => {
    describe('valid tokens', () => {
      it('should validate a valid logout token with sub', () => {
        const payload = createValidLogoutTokenPayload();
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
        expect(result.claims?.sub).toBe('user-123');
        expect(result.claims?.jti).toBe('unique-jti-123');
        expect(result.header?.alg).toBe('RS256');
      });

      it('should validate a valid logout token with sid', () => {
        const payload = {
          iss: defaultIssuer,
          aud: defaultAudience,
          iat: mockNow,
          exp: mockNow + 300,
          jti: 'unique-jti-456',
          sid: 'session-abc',
          events: {
            [BACKCHANNEL_LOGOUT_EVENT]: {},
          },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
        expect(result.claims?.sid).toBe('session-abc');
      });

      it('should validate a token with both sub and sid', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          sid: 'session-xyz',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
        expect(result.claims?.sub).toBe('user-123');
        expect(result.claims?.sid).toBe('session-xyz');
      });

      it('should validate a token with array audience', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          aud: ['other-client', defaultAudience],
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
      });
    });

    describe('invalid format', () => {
      it('should reject invalid JWT format', () => {
        const result = validator.validate('not-a-jwt', {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_format');
        expect(result.error).toContain('Invalid JWT format');
      });

      it('should reject JWT with wrong number of parts', () => {
        const result = validator.validate('header.payload', {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_format');
      });
    });

    describe('issuer validation', () => {
      it('should reject missing issuer', () => {
        const payload = createValidLogoutTokenPayload();
        delete payload.iss;
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_issuer');
      });

      it('should reject wrong issuer', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iss: 'https://wrong-issuer.com',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_issuer');
      });
    });

    describe('audience validation', () => {
      it('should reject missing audience', () => {
        const payload = createValidLogoutTokenPayload();
        delete payload.aud;
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_audience');
      });

      it('should reject wrong audience', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          aud: 'wrong-client',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_audience');
      });

      it('should reject when expected audience not in array', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          aud: ['other-client-1', 'other-client-2'],
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_audience');
      });
    });

    describe('events claim validation', () => {
      it('should reject missing events claim', () => {
        const payload = createValidLogoutTokenPayload();
        delete payload.events;
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
        expect(result.error).toContain('Missing or invalid events claim');
      });

      it('should reject missing back-channel logout event', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: { 'some-other-event': {} },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });

      it('should reject non-empty event object', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: { [BACKCHANNEL_LOGOUT_EVENT]: { extra: 'data' } },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
        expect(result.error).toContain('must be an empty object');
      });

      it('should reject null event object', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: { [BACKCHANNEL_LOGOUT_EVENT]: null },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });
    });

    describe('jti validation', () => {
      it('should reject missing jti', () => {
        const payload = createValidLogoutTokenPayload();
        delete payload.jti;
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('missing_jti');
      });
    });

    describe('sub/sid validation', () => {
      it('should reject token without sub or sid', () => {
        const payload = {
          iss: defaultIssuer,
          aud: defaultAudience,
          iat: mockNow,
          exp: mockNow + 300,
          jti: 'unique-jti-789',
          events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('missing_sub_and_sid');
      });
    });

    describe('nonce validation', () => {
      it('should reject token with nonce claim', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          nonce: 'should-not-be-here',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('nonce_present');
      });
    });

    describe('timing validation', () => {
      it('should reject expired token (exp in the past)', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          exp: mockNow - 100, // expired 100 seconds ago (beyond 30s clockSkew)
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('token_expired');
      });

      it('should accept token within exp clockSkew', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          exp: mockNow - 20, // expired 20 seconds ago (within 30s clockSkew)
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
      });

      it('should reject token missing exp claim', () => {
        const payload = createValidLogoutTokenPayload();
        delete payload.exp;
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('token_expired');
      });

      it('should reject token with iat too old', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow - 200, // 200 seconds ago (beyond default 60s maxAge + 30s clockSkew)
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('iat_too_old');
      });

      it('should accept token within maxAge', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow - 80, // 80 seconds ago (within default 60s + 30s tolerance)
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
      });

      it('should respect custom maxAge', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow - 200, // 200 seconds ago
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
          maxAge: 300, // Allow up to 300 seconds
          clockSkew: 0,
        });

        expect(result.valid).toBe(true);
      });

      it('should reject token issued in the future', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow + 100, // 100 seconds in the future (beyond 30s tolerance)
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('not_yet_valid');
      });

      it('should accept token slightly in the future (within clockSkew)', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow + 20, // 20 seconds in the future (within 30s tolerance)
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
      });
    });

    describe('expected sub/sid validation', () => {
      it('should validate matching expected sub', () => {
        const payload = createValidLogoutTokenPayload();
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
          expectedSub: 'user-123',
        });

        expect(result.valid).toBe(true);
      });

      it('should reject mismatched expected sub', () => {
        const payload = createValidLogoutTokenPayload();
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
          expectedSub: 'different-user',
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('sub_mismatch');
      });

      it('should validate matching expected sid', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          sid: 'session-123',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
          expectedSid: 'session-123',
        });

        expect(result.valid).toBe(true);
      });

      it('should reject mismatched expected sid', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          sid: 'session-123',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
          expectedSid: 'different-session',
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('sid_mismatch');
      });
    });
  });

  describe('extractClaims', () => {
    it('should extract claims from valid token', () => {
      const payload = createValidLogoutTokenPayload();
      const token = createMockJwt(defaultHeader, payload);

      const claims = validator.extractClaims(token);

      expect(claims).not.toBeNull();
      expect(claims?.iss).toBe(defaultIssuer);
      expect(claims?.sub).toBe('user-123');
    });

    it('should return null for invalid token', () => {
      const claims = validator.extractClaims('not-a-valid-jwt');
      expect(claims).toBeNull();
    });
  });

  describe('extractHeader', () => {
    it('should extract header from valid token', () => {
      const payload = createValidLogoutTokenPayload();
      const token = createMockJwt({ ...defaultHeader, kid: 'key-123' }, payload);

      const header = validator.extractHeader(token);

      expect(header).not.toBeNull();
      expect(header?.alg).toBe('RS256');
      expect(header?.kid).toBe('key-123');
    });

    it('should return null for invalid token', () => {
      const header = validator.extractHeader('not-a-valid-jwt');
      expect(header).toBeNull();
    });
  });

  describe('security edge cases', () => {
    describe('algorithm security', () => {
      it('should reject alg: none', () => {
        const payload = createValidLogoutTokenPayload();
        const token = createMockJwt({ alg: 'none', typ: 'JWT' }, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('insecure_algorithm');
      });

      it('should reject alg: None (case variation)', () => {
        const payload = createValidLogoutTokenPayload();
        const token = createMockJwt({ alg: 'None', typ: 'JWT' }, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('insecure_algorithm');
      });

      it('should reject alg: NONE (uppercase)', () => {
        const payload = createValidLogoutTokenPayload();
        const token = createMockJwt({ alg: 'NONE', typ: 'JWT' }, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('insecure_algorithm');
      });
    });

    describe('type confusion attacks', () => {
      it('should reject events claim as string', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: 'not-an-object',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });

      it('should reject events claim as array', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: [BACKCHANNEL_LOGOUT_EVENT],
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });

      it('should reject events claim as null', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: null,
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });

      it('should reject logout event as string', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: { [BACKCHANNEL_LOGOUT_EVENT]: 'string-value' },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });

      it('should reject logout event as array', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: { [BACKCHANNEL_LOGOUT_EVENT]: [] },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_events');
      });
    });

    describe('empty string attacks', () => {
      it('should reject empty issuer', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iss: '',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('invalid_issuer');
      });

      it('should reject empty jti', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          jti: '',
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('missing_jti');
      });

      it('should reject empty sub when no sid', () => {
        const payload = {
          iss: defaultIssuer,
          aud: defaultAudience,
          iat: mockNow,
          exp: mockNow + 300,
          jti: 'unique-jti',
          sub: '',
          events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('missing_sub_and_sid');
      });
    });

    describe('prototype pollution prevention', () => {
      it('should handle __proto__ in events safely', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          events: {
            [BACKCHANNEL_LOGOUT_EVENT]: {},
            __proto__: { polluted: true },
          },
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        // Should validate successfully - __proto__ is just a key
        expect(result.valid).toBe(true);
        // Verify no prototype pollution occurred
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
      });
    });

    describe('boundary conditions', () => {
      it('should handle iat exactly at maxAge boundary', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow - 90, // Exactly at 60s maxAge + 30s clockSkew boundary
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
      });

      it('should reject iat just past maxAge boundary', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow - 91, // 1 second past boundary
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('iat_too_old');
      });

      it('should handle iat exactly at future clockSkew boundary', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow + 30, // Exactly at clockSkew boundary
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(true);
      });

      it('should reject iat just past future clockSkew boundary', () => {
        const payload = {
          ...createValidLogoutTokenPayload(),
          iat: mockNow + 31, // 1 second past boundary
        };
        const token = createMockJwt(defaultHeader, payload);

        const result = validator.validate(token, {
          issuer: defaultIssuer,
          audience: defaultAudience,
        });

        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('not_yet_valid');
      });
    });
  });
});
