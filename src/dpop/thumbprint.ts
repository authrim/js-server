/**
 * JWK Thumbprint (RFC 7638)
 *
 * Computes a hash of a JWK for use as a key identifier.
 */

import type { CryptoProvider } from '../providers/crypto.js';

/**
 * Calculate JWK thumbprint
 *
 * Per RFC 7638, the thumbprint is computed as:
 * 1. Construct a JSON object with only the required members, in lexicographic order
 * 2. Compute SHA-256 hash of the UTF-8 encoding of the JSON
 * 3. Base64url encode the hash
 *
 * @param jwk - JSON Web Key
 * @param crypto - Crypto provider
 * @returns Base64url-encoded thumbprint
 */
export async function calculateJwkThumbprint(
  jwk: JsonWebKey,
  crypto: CryptoProvider
): Promise<string> {
  return crypto.calculateThumbprint(jwk);
}

/**
 * Verify that a JWK thumbprint matches the expected value
 *
 * @param jwk - JSON Web Key to verify
 * @param expectedThumbprint - Expected thumbprint value
 * @param crypto - Crypto provider
 * @returns true if thumbprints match
 */
export async function verifyJwkThumbprint(
  jwk: JsonWebKey,
  expectedThumbprint: string,
  crypto: CryptoProvider
): Promise<boolean> {
  const actualThumbprint = await calculateJwkThumbprint(jwk, crypto);
  return actualThumbprint === expectedThumbprint;
}
