/**
 * Integration Test: Back-Channel Logout Flow
 *
 * Tests the complete Back-Channel Logout flow including:
 * - Logout Token reception
 * - Claims validation
 * - Session identification
 *
 * NOTE: BackChannelLogoutValidator performs claims validation only.
 * Signature verification is done separately using JWKS + crypto.
 */

import { describe, it, expect } from 'vitest';
import { BackChannelLogoutValidator } from '../../src/session/back-channel-logout.js';

// Helper to create base64url encoded strings
function base64UrlEncode(input: string): string {
  return Buffer.from(input).toString('base64url');
}

// Helper to create a mock logout token
function createLogoutToken(header: object, payload: object, signature = 'mock-signature'): string {
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sigB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

describe('Integration: Back-Channel Logout Flow', () => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const validator = new BackChannelLogoutValidator();

  // Standard logout token claims
  const createValidLogoutPayload = (overrides: object = {}) => ({
    iss: 'https://auth.example.com',
    aud: 'https://api.example.com',
    sub: 'user-123',
    iat: nowSeconds,
    exp: nowSeconds + 300, // 5 minutes
    jti: 'unique-logout-token-id-12345',
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {},
    },
    ...overrides,
  });

  const validationOptions = {
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
  };

  describe('Scenario 1: Valid Logout Token Processing', () => {
    it('should validate logout token with sub claim', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ sub: 'user-to-logout' })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(true);
      expect(result.claims?.sub).toBe('user-to-logout');
      expect(result.claims?.jti).toBe('unique-logout-token-id-12345');
    });

    it('should validate logout token with sid claim', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ sid: 'session-12345', sub: undefined })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(true);
      expect(result.claims?.sid).toBe('session-12345');
    });

    it('should validate logout token with both sub and sid', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ sub: 'user-123', sid: 'session-456' })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(true);
      expect(result.claims?.sub).toBe('user-123');
      expect(result.claims?.sid).toBe('session-456');
    });
  });

  describe('Scenario 2: Logout Token Validation Failures', () => {
    it('should reject logout token without events claim', () => {
      const payload = createValidLogoutPayload();
      delete (payload as Record<string, unknown>).events;

      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        payload
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_events');
    });

    it('should reject logout token without jti claim', () => {
      const payload = createValidLogoutPayload();
      delete (payload as Record<string, unknown>).jti;

      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        payload
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('missing_jti');
    });

    it('should reject logout token with neither sub nor sid', () => {
      const payload = createValidLogoutPayload();
      delete (payload as Record<string, unknown>).sub;

      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        payload
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('missing_sub_and_sid');
    });

    it('should reject logout token with nonce claim (forbidden)', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ nonce: 'should-not-be-present' })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('nonce_present');
    });

    it('should reject logout token with alg: none', () => {
      const token = createLogoutToken(
        { alg: 'none', typ: 'logout+jwt' },
        createValidLogoutPayload()
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('insecure_algorithm');
    });
  });

  describe('Scenario 3: Issuer/Audience Validation', () => {
    it('should reject logout token with wrong issuer', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ iss: 'https://malicious.example.com' })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_issuer');
    });

    it('should reject logout token with wrong audience', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ aud: 'https://other-api.example.com' })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_audience');
    });

    it('should accept logout token with array audience containing expected value', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({
          aud: ['https://other.example.com', 'https://api.example.com'],
        })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(true);
    });
  });

  describe('Scenario 4: Time-based Validation', () => {
    it('should reject expired logout token', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({
          exp: nowSeconds - 600, // Expired 10 minutes ago
        })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('token_expired');
    });

    it('should reject logout token with iat too far in the past', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({
          iat: nowSeconds - 3600, // 1 hour ago
          exp: nowSeconds + 300,
        })
      );

      const result = validator.validate(token, {
        ...validationOptions,
        maxAge: 300, // 5 minutes max age
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('iat_too_old');
    });

    it('should reject logout token with iat in the future', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({
          iat: nowSeconds + 3600, // 1 hour in future
          exp: nowSeconds + 7200,
        })
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('not_yet_valid');
    });

    it('should accept logout token with iat within clock skew', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({
          iat: nowSeconds + 20, // 20 seconds in future
          exp: nowSeconds + 320,
        })
      );

      const result = validator.validate(token, {
        ...validationOptions,
        clockSkew: 30, // 30 seconds tolerance
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('Scenario 5: Expected Subject/Session Validation', () => {
    it('should reject logout token with wrong expected sub', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ sub: 'user-456' })
      );

      const result = validator.validate(token, {
        ...validationOptions,
        expectedSub: 'user-123', // Expecting different user
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('sub_mismatch');
    });

    it('should reject logout token with wrong expected sid', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ sub: 'user-123', sid: 'session-wrong' })
      );

      const result = validator.validate(token, {
        ...validationOptions,
        expectedSid: 'session-correct',
      });

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('sid_mismatch');
    });

    it('should accept logout token matching expected sub', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        createValidLogoutPayload({ sub: 'user-123' })
      );

      const result = validator.validate(token, {
        ...validationOptions,
        expectedSub: 'user-123',
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('Scenario 6: Real-World Logout Flow Simulation', () => {
    it('should handle complete logout flow: receive token → validate → extract session info', () => {
      // Simulate receiving logout token from AS
      const logoutToken = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-12345',
          sid: 'session-67890',
          iat: nowSeconds,
          exp: nowSeconds + 300,
          jti: 'logout-request-abc123',
          events: {
            'http://schemas.openid.net/event/backchannel-logout': {},
          },
        }
      );

      // Step 1: Validate the token (after signature verification in real flow)
      const result = validator.validate(logoutToken, validationOptions);
      expect(result.valid).toBe(true);

      // Step 2: Extract session information for invalidation
      const claims = result.claims!;
      expect(claims.sub).toBe('user-12345');
      expect(claims.sid).toBe('session-67890');
      expect(claims.jti).toBe('logout-request-abc123');

      // Step 3: Application would now:
      // - Check jti against replay cache (application responsibility)
      // - Invalidate session identified by sid or all sessions for sub
      // - Return HTTP 200 to the AS
    });

    it('should handle logout for all user sessions (sub only, no sid)', () => {
      // Logout token for all user sessions
      const logoutToken = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        {
          iss: 'https://auth.example.com',
          aud: 'https://api.example.com',
          sub: 'user-to-logout-everywhere',
          // No sid - means logout all sessions for this user
          iat: nowSeconds,
          exp: nowSeconds + 300,
          jti: 'global-logout-xyz',
          events: {
            'http://schemas.openid.net/event/backchannel-logout': {},
          },
        }
      );

      const result = validator.validate(logoutToken, validationOptions);

      expect(result.valid).toBe(true);
      expect(result.claims?.sub).toBe('user-to-logout-everywhere');
      expect(result.claims?.sid).toBeUndefined();

      // Application would invalidate ALL sessions for this user
    });
  });

  describe('Scenario 7: Malformed Token Handling', () => {
    it('should reject completely malformed token', () => {
      const result = validator.validate('not-a-jwt', validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_format');
    });

    it('should reject token with invalid base64', () => {
      const result = validator.validate('!!!.@@@.###', validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_format');
    });

    it('should reject token with wrong number of parts', () => {
      const result = validator.validate('header.payload', validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_format');
    });
  });

  describe('Scenario 8: Events Claim Validation', () => {
    it('should reject token with wrong event URI', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        {
          ...createValidLogoutPayload(),
          events: {
            'http://wrong.event.uri': {},
          },
        }
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_events');
    });

    it('should reject token with non-empty event object', () => {
      const token = createLogoutToken(
        { alg: 'RS256', typ: 'logout+jwt', kid: 'logout-key-1' },
        {
          ...createValidLogoutPayload(),
          events: {
            'http://schemas.openid.net/event/backchannel-logout': {
              someData: 'should not be here',
            },
          },
        }
      );

      const result = validator.validate(token, validationOptions);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('invalid_events');
    });
  });
});
