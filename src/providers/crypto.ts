/**
 * Crypto Provider Interface
 *
 * Platform-agnostic cryptographic operations abstraction for server-side JWT operations.
 * Implementations must be injected - @authrim/server does not use crypto.subtle directly.
 */

/**
 * Crypto Provider interface
 *
 * Implementations should:
 * - Use cryptographically secure operations
 * - Support RSA and ECDSA signature verification
 * - Implement JWK import for public keys
 * - Calculate JWK thumbprints per RFC 7638
 */
export interface CryptoProvider {
  /**
   * Verify a digital signature
   *
   * @param alg - JWA algorithm (e.g., 'RS256', 'ES256')
   * @param key - CryptoKey for verification
   * @param signature - Signature bytes
   * @param data - Data that was signed
   * @returns Promise resolving to true if signature is valid
   */
  verifySignature(
    alg: string,
    key: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array
  ): Promise<boolean>;

  /**
   * Import a JWK as a CryptoKey
   *
   * @param jwk - JSON Web Key
   * @param alg - Algorithm to use with the key
   * @returns Promise resolving to a CryptoKey
   */
  importJwk(jwk: JsonWebKey, alg: string): Promise<CryptoKey>;

  /**
   * Compute SHA-256 hash
   *
   * @param data - String or bytes to hash
   * @returns Promise resolving to hash bytes
   */
  sha256(data: string | Uint8Array): Promise<Uint8Array>;

  /**
   * Calculate JWK Thumbprint (RFC 7638)
   *
   * @param jwk - JSON Web Key (public key)
   * @returns Promise resolving to base64url-encoded thumbprint
   */
  calculateThumbprint(jwk: JsonWebKey): Promise<string>;
}
