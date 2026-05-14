/**
 * Configuration Type Definitions
 */

import type { HttpProvider } from '../providers/http.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type { ClockProvider } from '../providers/clock.js';
import type { CacheProvider } from '../providers/cache.js';
import type { CachedJwk } from './jwk.js';
import type { TokenValidationOptions } from './token.js';

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
   * If multiple issuers are configured, this means all issuers share the same JWKS.
   * Use jwksUriByIssuer when each tenant/issuer has its own JWKS endpoint.
   */
  jwksUri?: string;

  /**
   * JWKS endpoint URL by issuer.
   * Only configured issuers are accepted; this map is never used for arbitrary iss values.
   */
  jwksUriByIssuer?: Record<string, string>;

  /**
   * Discover JWKS from each allowed issuer's OpenID configuration when no explicit
   * jwksUri/jwksUriByIssuer entry exists.
   * @default true
   */
  dynamicJwksDiscovery?: boolean;

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
   * Token introspection endpoint by issuer.
   */
  introspectionEndpointByIssuer?: Record<string, string>;

  /**
   * Token revocation endpoint
   * Required for revocation operations
   */
  revocationEndpoint?: string;

  /**
   * Token revocation endpoint by issuer.
   */
  revocationEndpointByIssuer?: Record<string, string>;

  /**
   * Canonical Step-Up endpoint base.
   * Defaults to `{issuer}/auth/step-up`.
   */
  stepUpEndpoint?: string;

  /**
   * Canonical Step-Up endpoint base by issuer.
   */
  stepUpEndpointByIssuer?: Record<string, string>;

  /**
   * Client credentials for introspection/revocation
   */
  clientCredentials?: {
    clientId: string;
    clientSecret: string;
  };

  /**
   * Additional token validation rules beyond issuer/audience.
   */
  tokenValidation?: Omit<TokenValidationOptions, 'issuer' | 'audience'>;

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
  jwksUriByIssuer: Record<string, string>;
  dynamicJwksDiscovery: boolean;
  clockToleranceSeconds: number;
  jwksRefreshIntervalMs: number;
  introspectionEndpoint?: string;
  introspectionEndpointByIssuer: Record<string, string>;
  revocationEndpoint?: string;
  revocationEndpointByIssuer: Record<string, string>;
  stepUpEndpoint?: string;
  stepUpEndpointByIssuer: Record<string, string>;
  clientCredentials?: {
    clientId: string;
    clientSecret: string;
  };
  tokenValidation: Omit<TokenValidationOptions, 'issuer' | 'audience'>;
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
