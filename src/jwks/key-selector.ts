/**
 * JWKS Key Selection Algorithm
 *
 * This algorithm MUST be implemented identically across all language SDKs.
 *
 * 1. If token header contains `kid`:
 *    a. Find key where key.kid === header.kid AND key.use === 'sig' (or undefined)
 *    b. If not found AND cache is stale, refresh JWKS and retry ONCE
 *    c. If still not found, return error: jwks_key_not_found
 *
 * 2. If no `kid` in token header:
 *    a. Filter keys by: key.alg === header.alg AND key.use === 'sig' (or undefined)
 *    b. If exactly ONE key matches, use it
 *    c. If ZERO or MORE THAN ONE keys match, return error: jwks_key_ambiguous
 *
 * 3. Algorithm mismatch:
 *    - If key.alg is present AND key.alg !== header.alg, skip the key
 *
 * 4. Cache behavior:
 *    - Default TTL: 1 hour
 *    - Stale-while-revalidate: NOT implemented (fail-closed)
 *    - Thundering herd: Use single-flight pattern (one concurrent fetch per issuer)
 *
 * 5. Cache-Control header:
 *    - SHOULD be respected if present
 *    - max-age takes precedence over default TTL
 */

import type { PublicJwk, CachedJwk } from '../types/jwk.js';
import type { JwtHeader } from '../types/claims.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Key selection result
 */
export interface KeySelectionResult {
  key: CachedJwk | null;
  error: AuthrimServerError | null;
  needsRefresh: boolean;
}

/**
 * Check if a JWK is suitable for signature verification
 *
 * @param jwk - JWK to check
 * @returns true if the key can be used for signature verification
 */
function isSigningKey(jwk: PublicJwk): boolean {
  // Key must not be explicitly for encryption
  return jwk.use === undefined || jwk.use === 'sig';
}

/**
 * Check if a JWK's algorithm matches the token's algorithm
 *
 * @param jwk - JWK to check
 * @param tokenAlg - Algorithm from token header
 * @returns true if algorithms match (or key has no explicit algorithm)
 */
function algorithmMatches(jwk: PublicJwk, tokenAlg: string): boolean {
  // If key has no explicit algorithm, it can be used with any compatible algorithm
  if (jwk.alg === undefined) {
    return true;
  }
  // If key has explicit algorithm, it must match
  return jwk.alg === tokenAlg;
}

/**
 * Select a key by kid (Key ID)
 *
 * @param keys - Available keys
 * @param kid - Key ID from token header
 * @param alg - Algorithm from token header
 * @returns KeySelectionResult
 */
export function selectKeyByKid(
  keys: CachedJwk[],
  kid: string,
  alg: string
): KeySelectionResult {
  // Find key with matching kid
  const matchingKey = keys.find(
    (k) => k.jwk.kid === kid && isSigningKey(k.jwk) && algorithmMatches(k.jwk, alg)
  );

  if (matchingKey) {
    return { key: matchingKey, error: null, needsRefresh: false };
  }

  // Key not found - may need to refresh JWKS
  return {
    key: null,
    error: new AuthrimServerError(
      'jwks_key_not_found',
      `No key found with kid: ${kid}`
    ),
    needsRefresh: true,
  };
}

/**
 * Select a key by algorithm (when no kid is present)
 *
 * @param keys - Available keys
 * @param alg - Algorithm from token header
 * @returns KeySelectionResult
 */
export function selectKeyByAlgorithm(
  keys: CachedJwk[],
  alg: string
): KeySelectionResult {
  // Filter keys that match the algorithm
  const matchingKeys = keys.filter(
    (k) => isSigningKey(k.jwk) && algorithmMatches(k.jwk, alg)
  );

  if (matchingKeys.length === 1) {
    return { key: matchingKeys[0]!, error: null, needsRefresh: false };
  }

  if (matchingKeys.length === 0) {
    return {
      key: null,
      error: new AuthrimServerError(
        'jwks_key_ambiguous',
        `No keys found matching algorithm: ${alg}`
      ),
      needsRefresh: false,
    };
  }

  // Multiple keys match - ambiguous
  return {
    key: null,
    error: new AuthrimServerError(
      'jwks_key_ambiguous',
      `Multiple keys (${matchingKeys.length}) match algorithm: ${alg}. Token must include 'kid' header.`
    ),
    needsRefresh: false,
  };
}

/**
 * Select a key from JWKS based on token header
 *
 * @param keys - Available keys
 * @param header - JWT header
 * @returns KeySelectionResult
 */
export function selectKey(
  keys: CachedJwk[],
  header: JwtHeader
): KeySelectionResult {
  if (header.kid) {
    return selectKeyByKid(keys, header.kid, header.alg);
  }

  return selectKeyByAlgorithm(keys, header.alg);
}
