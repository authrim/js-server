/**
 * Configuration Type Definitions
 */

import type { HttpProvider } from '../providers/http.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type { ClockProvider } from '../providers/clock.js';
import type { CacheProvider } from '../providers/cache.js';
import type { CachedJwk } from './jwk.js';

/**
 * AuthrimServer configuration options
 */
export interface AuthrimServerConfig {
  /**
   * Expected token issuer(s)
   * This is compared against the `iss` claim in tokens
   */
  issuer: string | string[];

  /**
   * Expected audience(s) for this resource server
   * This is compared against the `aud` claim in tokens
   */
  audience: string | string[];

  /**
   * JWKS endpoint URL
   * If not provided, will be discovered from `{issuer}/.well-known/openid-configuration`
   */
  jwksUri?: string;

  /**
   * Clock tolerance in seconds for exp, nbf, iat validation
   * @default 60
   */
  clockToleranceSeconds?: number;

  /**
   * JWKS cache TTL in milliseconds
   * @default 3600000 (1 hour)
   */
  jwksRefreshIntervalMs?: number;

  /**
   * Token introspection endpoint
   * Required for introspection operations
   */
  introspectionEndpoint?: string;

  /**
   * Token revocation endpoint
   * Required for revocation operations
   */
  revocationEndpoint?: string;

  /**
   * Client credentials for introspection/revocation
   */
  clientCredentials?: {
    clientId: string;
    clientSecret: string;
  };

  // Provider injection

  /**
   * HTTP provider for network requests
   * @default fetchHttpProvider()
   */
  http?: HttpProvider;

  /**
   * Crypto provider for cryptographic operations
   * @default webCryptoProvider()
   */
  crypto?: CryptoProvider;

  /**
   * Clock provider for time operations
   * @default systemClock()
   */
  clock?: ClockProvider;

  /**
   * JWKS cache provider
   * @default memoryCache()
   */
  jwksCache?: CacheProvider<CachedJwk[]>;

  /**
   * Require HTTPS for issuer and JWKS URI
   * Set to false to allow HTTP in development environments
   * @default true
   */
  requireHttps?: boolean;
}

/**
 * Resolved configuration with all defaults applied
 */
export interface ResolvedAuthrimServerConfig {
  issuer: string[];
  audience: string[];
  jwksUri?: string;
  clockToleranceSeconds: number;
  jwksRefreshIntervalMs: number;
  introspectionEndpoint?: string;
  revocationEndpoint?: string;
  clientCredentials?: {
    clientId: string;
    clientSecret: string;
  };
  http: HttpProvider;
  crypto: CryptoProvider;
  clock: ClockProvider;
  jwksCache: CacheProvider<CachedJwk[]>;
  requireHttps: boolean;
}

/**
 * Memory cache options
 */
export interface MemoryCacheOptions {
  /** Default TTL in milliseconds */
  ttlMs?: number;
  /** Maximum number of entries */
  maxSize?: number;
}
