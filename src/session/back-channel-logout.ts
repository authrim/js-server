/**
 * Back-Channel Logout Validator
 *
 * Implements OpenID Connect Back-Channel Logout 1.0
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 *
 * Back-channel logout allows the OP to notify RPs of logout events
 * via direct HTTP calls (server-to-server).
 *
 * NOTE: This validator performs claims validation only.
 * JWT signature verification MUST be performed separately using JWKS.
 */

import type { LogoutTokenClaims } from '../types/session.js';
import type { JwtHeader } from '../types/claims.js';
import { parseJwt, InsecureAlgorithmError } from '../token/verify-jwt.js';
import { timingSafeEqual } from '../utils/timing-safe.js';

/**
 * Back-channel logout event URI
 */
export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/**
 * Back-channel logout validation error codes
 */
export type BackChannelLogoutErrorCode =
  | 'invalid_format'
  | 'insecure_algorithm'
  | 'invalid_issuer'
  | 'invalid_audience'
  | 'invalid_events'
  | 'token_expired'
  | 'iat_too_old'
  | 'not_yet_valid'
  | 'missing_sub_and_sid'
  | 'sub_mismatch'
  | 'sid_mismatch'
  | 'missing_jti'
  | 'nonce_present';

/**
 * Options for validating a logout token
 */
export interface BackChannelLogoutValidationOptions {
  /** Expected issuer */
  issuer: string;
  /** Expected audience (client_id) */
  audience: string;
  /** Maximum age in seconds (default: 60) */
  maxAge?: number;
  /** Clock skew tolerance in seconds (default: 30) */
  clockSkew?: number;
  /** Expected session ID (optional) */
  expectedSid?: string;
  /** Expected subject (optional) */
  expectedSub?: string;
}

/**
 * Result of back-channel logout token validation
 */
export interface BackChannelLogoutValidationResult {
  /** Whether the token is valid */
  valid: boolean;
  /** Validated claims (if valid) */
  claims?: LogoutTokenClaims;
  /** JWT header (if valid) */
  header?: JwtHeader;
  /** Error message (if invalid) */
  error?: string;
  /** Error code (if invalid) */
  errorCode?: BackChannelLogoutErrorCode;
}

/**
 * Back-Channel Logout Validator
 *
 * Validates logout_token JWTs per OIDC Back-Channel Logout 1.0.
 *
 * ## Security Notes
 *
 * 1. **JWT Signature Verification**: This class performs claims validation only.
 *    JWT signature verification MUST be performed separately using JWKS
 *    before calling validate(). The caller MUST reject tokens with alg: none.
 *
 * 2. **Algorithm Validation**: Per Section 2.6, "alg with the value none MUST NOT
 *    be used". This validator explicitly rejects alg: none tokens.
 *
 * 3. **JTI Replay Protection**: This validator checks for jti presence only.
 *    The application MUST implement jti replay protection by:
 *    - Storing used jti values (at least until token expiry + clock skew)
 *    - Rejecting tokens with previously-used jti values
 *
 * 4. **Expiration Validation**: Per Section 2.4, exp is REQUIRED. This validator
 *    checks that the token has not expired (with clock skew tolerance).
 *
 * Usage (Node.js server receiving back-channel logout request):
 * ```typescript
 * // 1. Receive logout_token from POST body
 * const logoutToken = req.body.logout_token;
 *
 * // 2. Verify JWT signature using JWKS (MUST reject alg: none)
 * const jwks = await jwksManager.getJwks();
 * const verified = await verifyJwtSignature(logoutToken, key, crypto);
 * if (!verified) {
 *   return res.status(400).send('Invalid signature');
 * }
 *
 * // 3. Validate claims (includes alg: none rejection)
 * const validator = new BackChannelLogoutValidator();
 * const result = validator.validate(logoutToken, {
 *   issuer: 'https://op.example.com',
 *   audience: 'my-client-id'
 * });
 *
 * if (!result.valid) {
 *   return res.status(400).send('Invalid logout token');
 * }
 *
 * // 4. Check for jti replay (application responsibility)
 * if (await jtiStore.has(result.claims.jti)) {
 *   return res.status(400).send('Token replay detected');
 * }
 * await jtiStore.set(result.claims.jti, true, result.claims.exp + clockSkew);
 *
 * // 5. Perform logout for sub and/or sid
 * await logoutUser(result.claims.sub, result.claims.sid);
 * ```
 */
export class BackChannelLogoutValidator {
  /**
   * Validate a logout_token
   *
   * Per OIDC Back-Channel Logout 1.0 Section 2.4 and 2.6, the logout_token MUST:
   * - Be a valid JWT with alg != "none"
   * - Contain iss, aud, iat, exp, jti claims
   * - Contain events claim with back-channel logout event
   * - Contain either sub or sid (or both)
   * - NOT contain a nonce claim
   * - NOT be expired (exp validation)
   *
   * @param logoutToken - JWT logout token to validate
   * @param options - Validation options
   * @returns Validation result
   */
  validate(
    logoutToken: string,
    options: BackChannelLogoutValidationOptions
  ): BackChannelLogoutValidationResult {
    // Decode JWT (without signature verification)
    let header: JwtHeader;
    let claims: LogoutTokenClaims;

    try {
      const decoded = parseJwt<LogoutTokenClaims>(logoutToken);
      header = decoded.header;
      claims = decoded.payload;
    } catch (error) {
      // Per Section 2.6: "alg with the value none MUST NOT be used"
      // parseJwt throws InsecureAlgorithmError for alg: none
      if (error instanceof InsecureAlgorithmError) {
        return {
          valid: false,
          error: 'Algorithm "none" is not allowed for logout tokens',
          errorCode: 'insecure_algorithm',
        };
      }
      return {
        valid: false,
        error: 'Invalid JWT format',
        errorCode: 'invalid_format',
      };
    }

    // Validate issuer using constant-time comparison to prevent timing attacks
    if (!claims.iss || !timingSafeEqual(claims.iss, options.issuer)) {
      return {
        valid: false,
        error: 'Issuer validation failed',
        errorCode: 'invalid_issuer',
      };
    }

    // Validate audience using constant-time comparison
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const audienceValid = audiences.some((aud) => timingSafeEqual(aud, options.audience));
    if (!audienceValid) {
      return {
        valid: false,
        error: 'Audience validation failed',
        errorCode: 'invalid_audience',
      };
    }

    // Validate events claim
    // Must contain the back-channel logout event with an empty object value
    if (!claims.events || typeof claims.events !== 'object') {
      return {
        valid: false,
        error: 'Missing or invalid events claim',
        errorCode: 'invalid_events',
      };
    }

    const logoutEvent = claims.events[BACKCHANNEL_LOGOUT_EVENT];
    if (logoutEvent === undefined) {
      return {
        valid: false,
        error: `Missing ${BACKCHANNEL_LOGOUT_EVENT} in events claim`,
        errorCode: 'invalid_events',
      };
    }

    // The event value MUST be an empty object {}
    // Check: must be object, not null, not array, and have no keys
    if (
      typeof logoutEvent !== 'object' ||
      logoutEvent === null ||
      Array.isArray(logoutEvent) ||
      Object.keys(logoutEvent).length !== 0
    ) {
      return {
        valid: false,
        error: 'Back-channel logout event must be an empty object',
        errorCode: 'invalid_events',
      };
    }

    // Validate jti (required for replay protection)
    if (!claims.jti) {
      return {
        valid: false,
        error: 'Missing jti claim',
        errorCode: 'missing_jti',
      };
    }

    // Validate that either sub or sid is present
    if (!claims.sub && !claims.sid) {
      return {
        valid: false,
        error: 'Logout token must contain either sub or sid (or both)',
        errorCode: 'missing_sub_and_sid',
      };
    }

    // Validate nonce is NOT present (per spec, logout tokens MUST NOT contain nonce)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if ('nonce' in claims && (claims as any).nonce !== undefined) {
      return {
        valid: false,
        error: 'Logout token must not contain nonce claim',
        errorCode: 'nonce_present',
      };
    }

    // Validate timing
    const now = Math.floor(Date.now() / 1000);
    const maxAge = options.maxAge ?? 60;
    const clockSkew = options.clockSkew ?? 30;

    // Per Section 2.4: exp is REQUIRED
    // Per Section 2.6 Step 3: Validate exp claim
    if (!claims.exp) {
      return {
        valid: false,
        error: 'Missing exp claim',
        errorCode: 'token_expired',
      };
    }

    // Check token is not expired (with clock skew tolerance)
    if (now > claims.exp + clockSkew) {
      return {
        valid: false,
        error: `Token expired at ${claims.exp}`,
        errorCode: 'token_expired',
      };
    }

    // Check iat is not too old (additional security measure)
    if (claims.iat && now - claims.iat > maxAge + clockSkew) {
      return {
        valid: false,
        error: `Token too old: iat ${claims.iat} is more than ${maxAge} seconds ago`,
        errorCode: 'iat_too_old',
      };
    }

    // Check iat is not in the future (with clock skew tolerance)
    if (claims.iat && claims.iat > now + clockSkew) {
      return {
        valid: false,
        error: `Token iat is in the future: ${claims.iat}`,
        errorCode: 'not_yet_valid',
      };
    }

    // Validate expected sub if provided
    // Use constant-time comparison to prevent timing attacks
    if (options.expectedSub && claims.sub && !timingSafeEqual(claims.sub, options.expectedSub)) {
      return {
        valid: false,
        error: 'Subject validation failed',
        errorCode: 'sub_mismatch',
      };
    }

    // Validate expected sid if provided
    // Use constant-time comparison to prevent timing attacks
    if (options.expectedSid && claims.sid && !timingSafeEqual(claims.sid, options.expectedSid)) {
      return {
        valid: false,
        error: 'Session ID validation failed',
        errorCode: 'sid_mismatch',
      };
    }

    return {
      valid: true,
      claims,
      header,
    };
  }

  /**
   * Extract claims from a logout token without validation
   *
   * Useful for inspecting the token before/during validation.
   *
   * @param logoutToken - JWT logout token
   * @returns Claims or null if invalid format
   */
  extractClaims(logoutToken: string): LogoutTokenClaims | null {
    try {
      const decoded = parseJwt<LogoutTokenClaims>(logoutToken);
      return decoded.payload;
    } catch {
      return null;
    }
  }

  /**
   * Extract header from a logout token without validation
   *
   * Useful for getting kid to select the correct JWKS key.
   *
   * @param logoutToken - JWT logout token
   * @returns Header or null if invalid format
   */
  extractHeader(logoutToken: string): JwtHeader | null {
    try {
      const decoded = parseJwt<LogoutTokenClaims>(logoutToken);
      return decoded.header;
    } catch {
      return null;
    }
  }
}
