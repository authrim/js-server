/**
 * AuthrimServer - Main entry point for the server SDK
 */

import type {
  AuthrimServerConfig,
  ResolvedAuthrimServerConfig,
} from '../types/config.js';
import type { TokenValidationResult, IntrospectionResponse } from '../types/token.js';
import type { DPoPValidationOptions, DPoPValidationResult } from '../types/dpop.js';
import type { CachedJwk } from '../types/jwk.js';
import { AuthrimServerError } from '../types/errors.js';
import { fetchHttpProvider } from '../providers-impl/fetch-http.js';
import { webCryptoProvider } from '../providers-impl/web-crypto.js';
import { systemClock } from '../providers-impl/system-clock.js';
import { memoryCache } from '../providers-impl/memory-cache.js';
import { JwksManager } from '../jwks/manager.js';
import { TokenValidator } from '../token/validator.js';
import { IntrospectionClient } from '../token/introspection.js';
import { RevocationClient } from '../token/revocation.js';
import { DPoPValidator } from '../dpop/validator.js';

/**
 * Validate URL uses HTTPS
 */
function validateHttps(url: string | undefined, name: string, requireHttps: boolean): void {
  if (!requireHttps || !url) {
    return;
  }

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') {
      throw new AuthrimServerError(
        'configuration_error',
        `${name} must use HTTPS: ${url}. Set requireHttps: false to allow HTTP in development.`
      );
    }
  } catch (error) {
    if (error instanceof AuthrimServerError) {
      throw error;
    }
    throw new AuthrimServerError(
      'configuration_error',
      `Invalid ${name} URL: ${url}`
    );
  }
}

/**
 * Resolve configuration with defaults
 */
function resolveConfig(config: AuthrimServerConfig): ResolvedAuthrimServerConfig {
  const issuer = Array.isArray(config.issuer) ? config.issuer : [config.issuer];
  const audience = Array.isArray(config.audience) ? config.audience : [config.audience];
  const requireHttps = config.requireHttps ?? true;

  // Validate HTTPS for security-critical URLs
  for (const iss of issuer) {
    validateHttps(iss, 'issuer', requireHttps);
  }
  validateHttps(config.jwksUri, 'jwksUri', requireHttps);
  validateHttps(config.introspectionEndpoint, 'introspectionEndpoint', requireHttps);
  validateHttps(config.revocationEndpoint, 'revocationEndpoint', requireHttps);

  return {
    issuer,
    audience,
    jwksUri: config.jwksUri,
    clockToleranceSeconds: config.clockToleranceSeconds ?? 60,
    jwksRefreshIntervalMs: config.jwksRefreshIntervalMs ?? 3600_000,
    introspectionEndpoint: config.introspectionEndpoint,
    revocationEndpoint: config.revocationEndpoint,
    clientCredentials: config.clientCredentials,
    http: config.http ?? fetchHttpProvider(),
    crypto: config.crypto ?? webCryptoProvider(),
    clock: config.clock ?? systemClock(),
    jwksCache: config.jwksCache ?? memoryCache<CachedJwk[]>({ ttlMs: config.jwksRefreshIntervalMs ?? 3600_000 }),
    requireHttps,
  };
}

/**
 * AuthrimServer
 *
 * Main class for server-side token validation and DPoP handling.
 */
export class AuthrimServer {
  private readonly config: ResolvedAuthrimServerConfig;
  private jwksManager: JwksManager | null = null;
  private tokenValidator: TokenValidator | null = null;
  private dpopValidator: DPoPValidator | null = null;
  private introspectionClient: IntrospectionClient | null = null;
  private revocationClient: RevocationClient | null = null;
  private initPromise: Promise<void> | null = null;
  private initialized = false;

  constructor(config: AuthrimServerConfig) {
    this.config = resolveConfig(config);
  }

  /**
   * Initialize the server (discovers JWKS endpoint if needed)
   *
   * This method is idempotent and thread-safe. Multiple concurrent calls
   * will wait for the same initialization to complete.
   */
  async init(): Promise<void> {
    // Fast path: already initialized
    if (this.initialized) {
      return;
    }

    // If an initialization is in progress, wait for it
    if (this.initPromise) {
      return this.initPromise;
    }

    // Start initialization
    this.initPromise = this.doInit();

    try {
      await this.initPromise;
      this.initialized = true;
    } catch (error) {
      // Reset promise on failure so subsequent calls can retry
      this.initPromise = null;
      throw error;
    }
  }

  private async doInit(): Promise<void> {
    // Discover JWKS URI if not provided
    let jwksUri = this.config.jwksUri;

    if (!jwksUri) {
      jwksUri = await this.discoverJwksUri();
    }

    // Initialize JWKS Manager
    this.jwksManager = new JwksManager({
      jwksUri,
      cacheTtlMs: this.config.jwksRefreshIntervalMs,
      http: this.config.http,
      crypto: this.config.crypto,
      clock: this.config.clock,
      cache: this.config.jwksCache,
    });

    // Initialize Token Validator
    this.tokenValidator = new TokenValidator({
      jwksManager: this.jwksManager,
      crypto: this.config.crypto,
      clock: this.config.clock,
      options: {
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockToleranceSeconds: this.config.clockToleranceSeconds,
      },
    });

    // Initialize DPoP Validator
    this.dpopValidator = new DPoPValidator(this.config.crypto, this.config.clock);

    // Initialize Introspection Client if endpoint is provided
    if (this.config.introspectionEndpoint && this.config.clientCredentials) {
      this.introspectionClient = new IntrospectionClient({
        endpoint: this.config.introspectionEndpoint,
        clientId: this.config.clientCredentials.clientId,
        clientSecret: this.config.clientCredentials.clientSecret,
        http: this.config.http,
      });
    }

    // Initialize Revocation Client if endpoint is provided
    if (this.config.revocationEndpoint && this.config.clientCredentials) {
      this.revocationClient = new RevocationClient({
        endpoint: this.config.revocationEndpoint,
        clientId: this.config.clientCredentials.clientId,
        clientSecret: this.config.clientCredentials.clientSecret,
        http: this.config.http,
      });
    }
  }

  /**
   * Discover JWKS URI from OpenID Configuration
   */
  private async discoverJwksUri(): Promise<string> {
    const issuer = this.config.issuer[0];
    if (!issuer) {
      throw new AuthrimServerError(
        'configuration_error',
        'No issuer configured'
      );
    }

    const configUrl = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;

    try {
      const response = await this.config.http.fetch(configUrl, {
        headers: { Accept: 'application/json' },
      });

      if (!response.ok) {
        // Consume response body to release the connection
        await response.text().catch(() => {});
        throw new AuthrimServerError(
          'configuration_error',
          `Failed to fetch OpenID Configuration: ${response.status}`
        );
      }

      const config = await response.json() as { jwks_uri?: string };

      if (!config.jwks_uri) {
        throw new AuthrimServerError(
          'configuration_error',
          'OpenID Configuration missing jwks_uri'
        );
      }

      // Validate HTTPS for discovered JWKS URI
      validateHttps(config.jwks_uri, 'discovered jwks_uri', this.config.requireHttps);

      return config.jwks_uri;
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }
      throw new AuthrimServerError(
        'configuration_error',
        `Failed to discover JWKS URI: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Validate a JWT access token
   *
   * @param token - JWT string
   * @returns Validation result
   */
  async validateToken(token: string): Promise<TokenValidationResult> {
    await this.init();

    if (!this.tokenValidator) {
      return {
        data: null,
        error: { code: 'configuration_error', message: 'Token validator not initialized' },
      };
    }

    return this.tokenValidator.validate(token);
  }

  /**
   * Validate a DPoP proof
   *
   * @param proof - DPoP proof JWT
   * @param options - Validation options
   * @returns Validation result
   */
  async validateDPoP(
    proof: string,
    options: DPoPValidationOptions
  ): Promise<DPoPValidationResult> {
    await this.init();

    if (!this.dpopValidator) {
      return {
        valid: false,
        errorCode: 'configuration_error',
        errorMessage: 'DPoP validator not initialized',
      };
    }

    return this.dpopValidator.validate(proof, options);
  }

  /**
   * Introspect a token
   *
   * @param token - Token to introspect
   * @param tokenTypeHint - Optional token type hint
   * @returns Introspection response
   */
  async introspect(
    token: string,
    tokenTypeHint?: 'access_token' | 'refresh_token'
  ): Promise<IntrospectionResponse> {
    await this.init();

    if (!this.introspectionClient) {
      throw new AuthrimServerError(
        'configuration_error',
        'Introspection endpoint not configured'
      );
    }

    return this.introspectionClient.introspect({
      token,
      token_type_hint: tokenTypeHint,
    });
  }

  /**
   * Revoke a token
   *
   * @param token - Token to revoke
   * @param tokenTypeHint - Optional token type hint
   */
  async revoke(
    token: string,
    tokenTypeHint?: 'access_token' | 'refresh_token'
  ): Promise<void> {
    await this.init();

    if (!this.revocationClient) {
      throw new AuthrimServerError(
        'configuration_error',
        'Revocation endpoint not configured'
      );
    }

    return this.revocationClient.revoke({
      token,
      token_type_hint: tokenTypeHint,
    });
  }

  /**
   * Get the resolved configuration
   */
  getConfig(): ResolvedAuthrimServerConfig {
    return this.config;
  }

  /**
   * Invalidate JWKS cache
   */
  invalidateJwksCache(): void {
    this.jwksManager?.invalidate();
  }
}

/**
 * Create an AuthrimServer instance
 *
 * @param config - Server configuration
 * @returns AuthrimServer instance
 */
export function createAuthrimServer(config: AuthrimServerConfig): AuthrimServer {
  return new AuthrimServer(config);
}
