/**
 * JWT Claims Validation
 *
 * RFC 7519 - JSON Web Token (JWT)
 *
 * This module handles claims validation (iss, aud, exp, nbf, iat).
 * Signature verification is handled separately in verify-jwt.ts.
 */

import type { StandardClaims } from '../types/claims.js';
import type { ClaimsValidationOptions, ClaimsValidationResult } from '../types/token.js';
import { timingSafeEqual } from '../utils/timing-safe.js';

/**
 * Validate JWT claims
 *
 * Validates:
 * - iss (issuer) - must match expected issuer
 * - aud (audience) - must include expected audience
 * - exp (expiration) - must not be expired (with tolerance)
 * - nbf (not before) - must be past nbf (with tolerance)
 * - iat (issued at) - must not be in the future (with tolerance)
 *
 * For ID Token validation (OIDC Core 1.0 Section 3.1.3.7), set:
 * - requireExp: true
 * - requireIat: true
 *
 * @param payload - JWT payload containing claims
 * @param options - Validation options
 * @returns Validation result
 */
export function validateClaims(
  payload: StandardClaims,
  options: ClaimsValidationOptions
): ClaimsValidationResult {
  const { issuer, audience, clockToleranceSeconds, now, requireExp, requireIat } = options;

  // Validate issuer
  const issuerResult = validateIssuer(payload.iss, issuer);
  if (!issuerResult.valid) {
    return issuerResult;
  }

  // Validate audience
  const audienceResult = validateAudience(payload.aud, audience);
  if (!audienceResult.valid) {
    return audienceResult;
  }

  // Validate expiration
  // Per OIDC Core 1.0 Section 3.1.3.7 Step 9: exp is REQUIRED for ID Tokens
  if (payload.exp !== undefined) {
    const expResult = validateExpiration(payload.exp, now, clockToleranceSeconds);
    if (!expResult.valid) {
      return expResult;
    }
  } else if (requireExp) {
    return {
      valid: false,
      error: { code: 'missing_exp', message: 'Missing required exp claim' },
    };
  }

  // Validate not before
  if (payload.nbf !== undefined) {
    const nbfResult = validateNotBefore(payload.nbf, now, clockToleranceSeconds);
    if (!nbfResult.valid) {
      return nbfResult;
    }
  }

  // Validate issued at (sanity check)
  // Per OIDC Core 1.0 Section 3.1.3.7 Step 10: iat is REQUIRED for ID Tokens
  if (payload.iat !== undefined) {
    const iatResult = validateIssuedAt(payload.iat, now, clockToleranceSeconds);
    if (!iatResult.valid) {
      return iatResult;
    }
  } else if (requireIat) {
    return {
      valid: false,
      error: { code: 'missing_iat', message: 'Missing required iat claim' },
    };
  }

  return { valid: true };
}

/**
 * Validate issuer claim
 */
function validateIssuer(
  iss: string | undefined,
  expectedIssuers: string | string[]
): ClaimsValidationResult {
  // Check for missing or empty issuer
  if (iss === undefined || iss === '') {
    return {
      valid: false,
      error: { code: 'invalid_issuer', message: 'Missing or empty issuer claim' },
    };
  }

  const issuers = Array.isArray(expectedIssuers) ? expectedIssuers : [expectedIssuers];

  // Filter out empty strings from expected issuers
  const validIssuers = issuers.filter((i) => i !== '');
  if (validIssuers.length === 0) {
    return {
      valid: false,
      error: { code: 'invalid_issuer', message: 'No valid expected issuers configured' },
    };
  }

  // Use timing-safe comparison to prevent timing attacks
  const issuerValid = validIssuers.some((expectedIss) => timingSafeEqual(iss, expectedIss));
  if (!issuerValid) {
    return {
      valid: false,
      error: { code: 'invalid_issuer', message: `Invalid issuer: ${iss}` },
    };
  }

  return { valid: true };
}

/**
 * Validate audience claim
 */
function validateAudience(
  aud: string | string[] | undefined,
  expectedAudiences: string | string[]
): ClaimsValidationResult {
  if (aud === undefined) {
    return {
      valid: false,
      error: { code: 'invalid_audience', message: 'Missing audience claim' },
    };
  }

  const audiences = Array.isArray(expectedAudiences) ? expectedAudiences : [expectedAudiences];
  const tokenAudiences = Array.isArray(aud) ? aud : [aud];

  // Filter out empty strings
  const validAudiences = audiences.filter((a) => a !== '');
  const validTokenAudiences = tokenAudiences.filter((a) => a !== '');

  if (validAudiences.length === 0) {
    return {
      valid: false,
      error: { code: 'invalid_audience', message: 'No valid expected audiences configured' },
    };
  }

  if (validTokenAudiences.length === 0) {
    return {
      valid: false,
      error: { code: 'invalid_audience', message: 'Token has no valid audience claims' },
    };
  }

  // Check if any expected audience is in token audiences
  // Use timing-safe comparison to prevent timing attacks
  const hasValidAudience = validTokenAudiences.some((tokenAud) =>
    validAudiences.some((expectedAud) => timingSafeEqual(tokenAud, expectedAud))
  );

  if (!hasValidAudience) {
    return {
      valid: false,
      error: {
        code: 'invalid_audience',
        message: `Invalid audience: ${validTokenAudiences.join(', ')}`,
      },
    };
  }

  return { valid: true };
}

/**
 * Maximum reasonable Unix timestamp (year 3000)
 * Prevents Date overflow and unrealistic token lifetimes
 */
const MAX_REASONABLE_TIMESTAMP = 32503680000; // 3000-01-01 00:00:00 UTC

/**
 * Minimum reasonable Unix timestamp (year 1970)
 */
const MIN_REASONABLE_TIMESTAMP = 0;

/**
 * Validate that a claim value is a finite number within reasonable bounds
 *
 * Per RFC 7519 Section 2, NumericDate values are numbers representing
 * seconds since Unix epoch. Non-numeric values must be rejected.
 * Additionally, we validate bounds to prevent Date overflow issues.
 */
function isValidNumericClaim(value: unknown): value is number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return false;
  }
  // Validate bounds to prevent Date overflow and unrealistic values
  return value >= MIN_REASONABLE_TIMESTAMP && value <= MAX_REASONABLE_TIMESTAMP;
}

/**
 * Validate expiration claim
 */
function validateExpiration(
  exp: unknown,
  now: number,
  tolerance: number
): ClaimsValidationResult {
  // Validate type first - must be a finite number per RFC 7519
  if (!isValidNumericClaim(exp)) {
    return {
      valid: false,
      error: {
        code: 'invalid_exp',
        message: 'Invalid exp claim: must be a number',
      },
    };
  }

  // Token is expired if exp + tolerance < now
  if (exp + tolerance < now) {
    return {
      valid: false,
      error: {
        code: 'token_expired',
        message: `Token expired at ${new Date(exp * 1000).toISOString()}`,
      },
    };
  }

  return { valid: true };
}

/**
 * Validate not before claim
 */
function validateNotBefore(
  nbf: unknown,
  now: number,
  tolerance: number
): ClaimsValidationResult {
  // Validate type first - must be a finite number per RFC 7519
  if (!isValidNumericClaim(nbf)) {
    return {
      valid: false,
      error: {
        code: 'invalid_nbf',
        message: 'Invalid nbf claim: must be a number',
      },
    };
  }

  // Token is not yet valid if nbf - tolerance > now
  if (nbf - tolerance > now) {
    return {
      valid: false,
      error: {
        code: 'token_not_yet_valid',
        message: `Token not valid until ${new Date(nbf * 1000).toISOString()}`,
      },
    };
  }

  return { valid: true };
}

/**
 * Validate issued at claim (sanity check)
 *
 * Per RFC 7519 Section 4.1.6, the iat claim identifies the time at which
 * the JWT was issued. A token with iat significantly in the future
 * indicates either clock skew or a potentially malicious token.
 */
function validateIssuedAt(
  iat: unknown,
  now: number,
  tolerance: number
): ClaimsValidationResult {
  // Validate type first - must be a finite number per RFC 7519
  if (!isValidNumericClaim(iat)) {
    return {
      valid: false,
      error: {
        code: 'invalid_iat',
        message: 'Invalid iat claim: must be a number',
      },
    };
  }

  // Token was issued in the future (with tolerance)
  if (iat - tolerance > now) {
    return {
      valid: false,
      error: {
        code: 'iat_in_future',
        message: `Token issued in the future: ${new Date(iat * 1000).toISOString()}`,
      },
    };
  }

  return { valid: true };
}

/**
 * Calculate time remaining until token expiration
 *
 * @param exp - Expiration timestamp (Unix seconds)
 * @param now - Current timestamp (Unix seconds)
 * @returns Seconds until expiration, or undefined if no exp claim
 */
export function getExpiresIn(exp: number | undefined, now: number): number | undefined {
  if (exp === undefined) {
    return undefined;
  }
  return Math.max(0, exp - now);
}
