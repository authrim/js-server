/**
 * JWKS Manager
 *
 * Handles JWKS fetching, caching, and key rotation.
 */

import type { HttpProvider } from '../providers/http.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type { ClockProvider } from '../providers/clock.js';
import type { CacheProvider } from '../providers/cache.js';
import type { PublicJwk, JwkSet, CachedJwk } from '../types/jwk.js';
import type { JwtHeader } from '../types/claims.js';
import { AuthrimServerError } from '../types/errors.js';
import { selectKey, type KeySelectionResult } from './key-selector.js';

/**
 * JWKS Manager configuration
 */
export interface JwksManagerConfig {
  /** JWKS endpoint URL */
  jwksUri: string;
  /** Cache TTL in milliseconds */
  cacheTtlMs: number;
  /** HTTP provider */
  http: HttpProvider;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Clock provider */
  clock: ClockProvider;
  /** Cache provider */
  cache: CacheProvider<CachedJwk[]>;
  /**
   * Optional callback for key import warnings
   * Called when a key fails to import (may be encryption key, unsupported algorithm, etc.)
   */
  onKeyImportWarning?: (warning: KeyImportWarning) => void;
  /**
   * Allow redirects to different hosts (default: false)
   *
   * SECURITY: By default, JWKS fetches will fail if redirected to a different host
   * to prevent SSRF attacks. Only enable this if you explicitly trust the issuer
   * to redirect to arbitrary hosts.
   */
  allowCrossOriginRedirect?: boolean;
}

/**
 * Key import warning information
 */
export interface KeyImportWarning {
  /** Key ID (if present) */
  kid?: string;
  /** Key type */
  kty: string;
  /** Algorithm (if present) */
  alg?: string;
  /** Reason for failure */
  reason: 'unsupported_algorithm' | 'import_failed' | 'unknown_key_type';
  /** Error message */
  message: string;
}

/**
 * Single-flight state for preventing thundering herd
 */
interface InFlightRequest {
  promise: Promise<CachedJwk[]>;
  startedAt: number;
}

/**
 * JWKS Manager
 *
 * Features:
 * - Automatic JWKS fetching and caching
 * - Key rotation handling (retry on kid not found)
 * - Single-flight pattern (one concurrent fetch per issuer)
 * - Cache-Control header support
 */
export class JwksManager {
  private readonly config: JwksManagerConfig;
  private readonly cacheKey: string;
  private inFlight: InFlightRequest | null = null;

  constructor(config: JwksManagerConfig) {
    this.config = config;
    this.cacheKey = `jwks:${config.jwksUri}`;
  }

  /**
   * Get a key for verifying a JWT
   *
   * Implements the key selection algorithm with automatic refresh on key not found.
   *
   * @param header - JWT header
   * @returns Selected key or error
   */
  async getKey(header: JwtHeader): Promise<KeySelectionResult> {
    // Try to get keys from cache
    let keys = await this.getKeys();

    // First attempt at key selection
    let result = selectKey(keys, header);

    // If key not found and we might need to refresh, try once more
    if (result.error && result.needsRefresh) {
      // Force refresh
      keys = await this.fetchAndCacheKeys();
      result = selectKey(keys, header);
    }

    return result;
  }

  /**
   * Get cached keys or fetch if not available
   */
  private async getKeys(): Promise<CachedJwk[]> {
    // Check cache first
    const cached = this.config.cache.get(this.cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch and cache
    return this.fetchAndCacheKeys();
  }

  /**
   * Fetch JWKS and cache keys
   *
   * Uses single-flight pattern to prevent thundering herd.
   */
  private async fetchAndCacheKeys(): Promise<CachedJwk[]> {
    // Check for in-flight request (single-flight pattern)
    if (this.inFlight) {
      const age = this.config.clock.nowMs() - this.inFlight.startedAt;
      // If request is still recent (< 30s), wait for it
      if (age < 30_000) {
        return this.inFlight.promise;
      }
      // Otherwise, start a new request
    }

    // Start new request
    const promise = this.doFetchAndCache();
    this.inFlight = {
      promise,
      startedAt: this.config.clock.nowMs(),
    };

    try {
      const keys = await promise;
      return keys;
    } finally {
      this.inFlight = null;
    }
  }

  /**
   * Actually fetch and cache keys
   */
  private async doFetchAndCache(): Promise<CachedJwk[]> {
    try {
      const response = await this.config.http.fetch(this.config.jwksUri, {
        headers: {
          Accept: 'application/json',
        },
      });

      // Security: Check for cross-origin redirects to prevent SSRF
      // If the response URL differs from the request URL, validate the redirect
      if (!this.config.allowCrossOriginRedirect && response.url) {
        const requestedUrl = new URL(this.config.jwksUri);
        const responseUrl = new URL(response.url);

        if (requestedUrl.host !== responseUrl.host) {
          throw new AuthrimServerError(
            'jwks_fetch_error',
            `JWKS fetch was redirected to a different host: ${responseUrl.host} (from ${requestedUrl.host}). ` +
              'This is blocked for security. Set allowCrossOriginRedirect: true if this is intentional.'
          );
        }
      }

      if (!response.ok) {
        // Consume response body to release the connection
        await response.text().catch(() => {});
        throw new AuthrimServerError(
          'jwks_fetch_error',
          `Failed to fetch JWKS: ${response.status} ${response.statusText}`
        );
      }

      const jwks = (await response.json()) as JwkSet;

      if (!jwks.keys || !Array.isArray(jwks.keys)) {
        throw new AuthrimServerError(
          'jwks_fetch_error',
          'Invalid JWKS response: missing keys array'
        );
      }

      // Import keys
      const cachedKeys: CachedJwk[] = [];
      for (const jwk of jwks.keys) {
        try {
          // Determine algorithm for import
          const alg = this.determineAlgorithm(jwk);
          if (!alg) {
            // Report warning for keys without determinable algorithm
            this.config.onKeyImportWarning?.({
              kid: jwk.kid,
              kty: jwk.kty,
              alg: jwk.alg,
              reason: jwk.kty === 'RSA' || jwk.kty === 'EC' || jwk.kty === 'OKP'
                ? 'unsupported_algorithm'
                : 'unknown_key_type',
              message: `Cannot determine algorithm for key: kty=${jwk.kty}, alg=${jwk.alg ?? 'none'}`,
            });
            continue;
          }

          const cryptoKey = await this.config.crypto.importJwk(jwk as JsonWebKey, alg);
          cachedKeys.push({ jwk, cryptoKey });
        } catch (error) {
          // Report warning for keys that fail to import
          this.config.onKeyImportWarning?.({
            kid: jwk.kid,
            kty: jwk.kty,
            alg: jwk.alg,
            reason: 'import_failed',
            message: `Failed to import key: ${error instanceof Error ? error.message : 'Unknown error'}`,
          });
          continue;
        }
      }

      // Determine cache TTL from Cache-Control header
      const cacheTtl = this.parseCacheControl(response.headers.get('Cache-Control'));

      // Cache keys
      this.config.cache.set(this.cacheKey, cachedKeys, cacheTtl);

      return cachedKeys;
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }
      throw new AuthrimServerError(
        'jwks_fetch_error',
        `Failed to fetch JWKS: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Determine the algorithm for a JWK
   */
  private determineAlgorithm(jwk: PublicJwk): string | null {
    // Use explicit algorithm if present
    if (jwk.alg) {
      return jwk.alg;
    }

    // Infer from key type and curve
    if (jwk.kty === 'RSA') {
      return 'RS256'; // Default for RSA
    }

    if (jwk.kty === 'EC') {
      const curveAlgMap: Record<string, string> = {
        'P-256': 'ES256',
        'P-384': 'ES384',
        'P-521': 'ES512',
      };
      return curveAlgMap[jwk.crv] ?? null;
    }

    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
      return 'EdDSA';
    }

    return null;
  }

  /**
   * Maximum cache TTL (24 hours) to prevent overflow and unreasonable cache times
   */
  private static readonly MAX_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

  /**
   * Parse Cache-Control header for max-age
   *
   * @param header - Cache-Control header value
   * @returns TTL in milliseconds
   */
  private parseCacheControl(header: string | null): number {
    if (!header) {
      return this.config.cacheTtlMs;
    }

    // Look for max-age directive
    const maxAgeMatch = header.match(/max-age=(\d+)/);
    if (maxAgeMatch && maxAgeMatch[1]) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (!isNaN(maxAge) && maxAge > 0) {
        // Cap at MAX_CACHE_TTL_MS to prevent overflow and excessive caching
        const maxAgeMs = Math.min(maxAge * 1000, JwksManager.MAX_CACHE_TTL_MS);
        return maxAgeMs;
      }
    }

    return this.config.cacheTtlMs;
  }

  /**
   * Invalidate cached keys
   */
  invalidate(): void {
    this.config.cache.delete(this.cacheKey);
  }
}
