/**
 * AuthrimServer - Main entry point for the server SDK
 */

import type {
  AuthrimServerConfig,
  ResolvedAuthrimServerConfig,
} from '../types/config.js';
import type {
  TokenValidationResult,
  IntrospectionResponse,
  TokenTypeHint,
} from '../types/token.js';
import type { ValidatedToken } from '../types/claims.js';
import type {
  StepUpActionResponse,
  StepUpCompleteRequest,
  StepUpResendResponse,
  StepUpStartRequest,
} from '../types/step-up.js';
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
import {
  StepUpClient,
  type StepUpIdempotentRequestOptions,
  type StepUpRequestOptions,
} from '../step-up/client.js';
import {
  CustomerProfileClient,
  type CustomerProfileDelegatedWriteOptions,
  type CustomerProfileRequestOptions,
  type CustomerProfileUpdateInput,
} from '../product/customer-profile.js';
import {
  readResponseJsonWithLimit,
  readResponseTextPreview,
} from '../utils/response-limits.js';

const MAX_DISCOVERY_RESPONSE_BYTES = 64 * 1024;

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

function getDefaultStepUpEndpoint(issuer: string | undefined): string {
  if (!issuer) {
    throw new AuthrimServerError(
      'configuration_error',
      'No issuer configured'
    );
  }
  return `${issuer.replace(/\/$/, '')}/auth/step-up`;
}

function normalizeIssuer(issuer: string): string {
  return issuer.replace(/\/$/, '');
}

function validateUrlMap(
  map: Record<string, string> | undefined,
  name: string,
  requireHttps: boolean
): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [issuer, endpoint] of Object.entries(map ?? {})) {
    validateHttps(issuer, `${name} issuer`, requireHttps);
    validateHttps(endpoint, `${name}[${issuer}]`, requireHttps);
    normalized[normalizeIssuer(issuer)] = endpoint;
  }
  return normalized;
}

/**
 * Resolve configuration with defaults
 */
function resolveConfig(config: AuthrimServerConfig): ResolvedAuthrimServerConfig {
  const issuer = (Array.isArray(config.issuer) ? config.issuer : [config.issuer]).map(normalizeIssuer);
  const audience = Array.isArray(config.audience) ? config.audience : [config.audience];
  const requireHttps = config.requireHttps ?? true;

  // Validate HTTPS for security-critical URLs
  for (const iss of issuer) {
    validateHttps(iss, 'issuer', requireHttps);
  }
  validateHttps(config.jwksUri, 'jwksUri', requireHttps);
  validateHttps(config.introspectionEndpoint, 'introspectionEndpoint', requireHttps);
  validateHttps(config.revocationEndpoint, 'revocationEndpoint', requireHttps);
  validateHttps(config.stepUpEndpoint, 'stepUpEndpoint', requireHttps);

  const jwksUriByIssuer = validateUrlMap(config.jwksUriByIssuer, 'jwksUriByIssuer', requireHttps);
  const introspectionEndpointByIssuer = validateUrlMap(
    config.introspectionEndpointByIssuer,
    'introspectionEndpointByIssuer',
    requireHttps
  );
  const revocationEndpointByIssuer = validateUrlMap(
    config.revocationEndpointByIssuer,
    'revocationEndpointByIssuer',
    requireHttps
  );
  const stepUpEndpointByIssuer = validateUrlMap(
    config.stepUpEndpointByIssuer,
    'stepUpEndpointByIssuer',
    requireHttps
  );

  return {
    issuer,
    audience,
    jwksUri: config.jwksUri,
    jwksUriByIssuer,
    dynamicJwksDiscovery: config.dynamicJwksDiscovery ?? true,
    clockToleranceSeconds: config.clockToleranceSeconds ?? 60,
    jwksRefreshIntervalMs: config.jwksRefreshIntervalMs ?? 3600_000,
    introspectionEndpoint: config.introspectionEndpoint,
    introspectionEndpointByIssuer,
    revocationEndpoint: config.revocationEndpoint,
    revocationEndpointByIssuer,
    stepUpEndpoint: config.stepUpEndpoint,
    stepUpEndpointByIssuer,
    clientCredentials: config.clientCredentials,
    tokenValidation: config.tokenValidation ?? {},
    http: config.http ?? fetchHttpProvider(),
    crypto: config.crypto ?? webCryptoProvider(),
    clock: config.clock ?? systemClock(),
    jwksCache: config.jwksCache ?? memoryCache<CachedJwk[]>({ ttlMs: config.jwksRefreshIntervalMs ?? 3600_000 }),
    requireHttps,
  };
}

export interface AuthrimServerStepUpNamespace {
  start(
    request: StepUpStartRequest,
    options?: AuthrimServerStepUpRequestOptions
  ): Promise<StepUpActionResponse>;
  getAction(
    actionId: string,
    options?: AuthrimServerStepUpRequestOptions
  ): Promise<StepUpActionResponse>;
  complete<Input = unknown>(
    actionId: string,
    request: StepUpCompleteRequest<Input>,
    options?: AuthrimServerStepUpIdempotentRequestOptions
  ): Promise<StepUpActionResponse>;
  resend(
    actionId: string,
    options?: AuthrimServerStepUpIdempotentRequestOptions
  ): Promise<StepUpResendResponse>;
  cancel(
    actionId: string,
    options?: AuthrimServerStepUpRequestOptions
  ): Promise<StepUpActionResponse>;
}

export interface AuthrimServerIssuerOptions {
  /** Explicit issuer for helper APIs when multiple issuers are configured. */
  issuer?: string;
  /** Validated token context; preferred over the explicit issuer option. */
  token?: ValidatedToken;
}

export type AuthrimServerStepUpRequestOptions = StepUpRequestOptions & AuthrimServerIssuerOptions;
export type AuthrimServerStepUpIdempotentRequestOptions =
  StepUpIdempotentRequestOptions & AuthrimServerIssuerOptions;

/**
 * AuthrimServer
 *
 * Main class for server-side token validation and DPoP handling.
 */
export class AuthrimServer {
  private readonly config: ResolvedAuthrimServerConfig;
  private jwksManagers = new Map<string, JwksManager>();
  private tokenValidator: TokenValidator | null = null;
  private dpopValidator: DPoPValidator | null = null;
  private introspectionClients = new Map<string, IntrospectionClient>();
  private revocationClients = new Map<string, RevocationClient>();
  private stepUpClients = new Map<string, StepUpClient>();
  private customerProfileClients = new Map<string, CustomerProfileClient>();
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
    // Initialize Token Validator
    this.tokenValidator = new TokenValidator({
      jwksManagerResolver: (issuer) => this.getJwksManagerForIssuer(issuer),
      crypto: this.config.crypto,
      clock: this.config.clock,
      options: {
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockToleranceSeconds: this.config.clockToleranceSeconds,
        ...this.config.tokenValidation,
      },
    });

    // Initialize DPoP Validator
    this.dpopValidator = new DPoPValidator(this.config.crypto, this.config.clock);

    // Preserve the historical single-issuer init behavior: configuration problems
    // in discovery are surfaced during init instead of the first token validation.
    if (!this.config.jwksUri && Object.keys(this.config.jwksUriByIssuer).length === 0) {
      if (this.config.issuer.length === 1 && this.config.issuer[0]) {
        await this.getJwksManagerForIssuer(this.config.issuer[0]);
      }
    }
  }

  /**
   * Discover JWKS URI from OpenID Configuration
   */
  private async discoverJwksUri(issuer: string): Promise<string> {
    const configUrl = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;

    try {
      const response = await this.config.http.fetch(configUrl, {
        headers: { Accept: 'application/json' },
      });

      if (!response.ok) {
        // Consume response body to release the connection
        await readResponseTextPreview(response, 1024).catch(() => {});
        throw new AuthrimServerError(
          'configuration_error',
          `Failed to fetch OpenID Configuration: ${response.status}`
        );
      }

      const config = await readResponseJsonWithLimit<{ jwks_uri?: string }>(
        response,
        MAX_DISCOVERY_RESPONSE_BYTES
      );

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

  private assertAllowedIssuer(issuer: string): string {
    const normalized = normalizeIssuer(issuer);
    if (!this.config.issuer.includes(normalized)) {
      throw new AuthrimServerError('invalid_issuer', `Issuer is not configured: ${normalized}`);
    }
    return normalized;
  }

  private resolveIssuer(options?: AuthrimServerIssuerOptions): string {
    if (options?.token?.issuer) {
      return this.assertAllowedIssuer(options.token.issuer);
    }
    if (options?.issuer) {
      return this.assertAllowedIssuer(options.issuer);
    }
    if (this.config.issuer.length === 1 && this.config.issuer[0]) {
      return this.config.issuer[0];
    }
    throw new AuthrimServerError(
      'configuration_error',
      'issuer or validated token context is required when multiple issuers are configured'
    );
  }

  private async getJwksManagerForIssuer(issuer: string): Promise<JwksManager> {
    const normalizedIssuer = this.assertAllowedIssuer(issuer);
    const existing = this.jwksManagers.get(normalizedIssuer);
    if (existing) {
      return existing;
    }

    let jwksUri = this.config.jwksUriByIssuer[normalizedIssuer] ?? this.config.jwksUri;
    if (!jwksUri) {
      if (!this.config.dynamicJwksDiscovery) {
        throw new AuthrimServerError(
          'configuration_error',
          `JWKS URI is not configured for issuer: ${normalizedIssuer}`
        );
      }
      jwksUri = await this.discoverJwksUri(normalizedIssuer);
    }

    const manager = new JwksManager({
      jwksUri,
      cacheTtlMs: this.config.jwksRefreshIntervalMs,
      http: this.config.http,
      crypto: this.config.crypto,
      clock: this.config.clock,
      cache: this.config.jwksCache,
    });
    this.jwksManagers.set(normalizedIssuer, manager);
    return manager;
  }

  private getIntrospectionClientForIssuer(issuer: string): IntrospectionClient {
    const normalizedIssuer = this.assertAllowedIssuer(issuer);
    const endpoint =
      this.config.introspectionEndpointByIssuer[normalizedIssuer] ??
      this.config.introspectionEndpoint;
    if (!endpoint || !this.config.clientCredentials) {
      throw new AuthrimServerError(
        'configuration_error',
        'Introspection endpoint not configured'
      );
    }

    const existing = this.introspectionClients.get(normalizedIssuer);
    if (existing) {
      return existing;
    }
    const client = new IntrospectionClient({
      endpoint,
      clientId: this.config.clientCredentials.clientId,
      clientSecret: this.config.clientCredentials.clientSecret,
      http: this.config.http,
    });
    this.introspectionClients.set(normalizedIssuer, client);
    return client;
  }

  private getRevocationClientForIssuer(issuer: string): RevocationClient {
    const normalizedIssuer = this.assertAllowedIssuer(issuer);
    const endpoint =
      this.config.revocationEndpointByIssuer[normalizedIssuer] ??
      this.config.revocationEndpoint;
    if (!endpoint || !this.config.clientCredentials) {
      throw new AuthrimServerError(
        'configuration_error',
        'Revocation endpoint not configured'
      );
    }

    const existing = this.revocationClients.get(normalizedIssuer);
    if (existing) {
      return existing;
    }
    const client = new RevocationClient({
      endpoint,
      clientId: this.config.clientCredentials.clientId,
      clientSecret: this.config.clientCredentials.clientSecret,
      http: this.config.http,
    });
    this.revocationClients.set(normalizedIssuer, client);
    return client;
  }

  private getStepUpClientForIssuer(issuer: string): StepUpClient {
    const normalizedIssuer = this.assertAllowedIssuer(issuer);
    const endpoint =
      this.config.stepUpEndpointByIssuer[normalizedIssuer] ??
      this.config.stepUpEndpoint ??
      getDefaultStepUpEndpoint(normalizedIssuer);
    const existing = this.stepUpClients.get(normalizedIssuer);
    if (existing) {
      return existing;
    }
    const client = new StepUpClient({
      endpoint,
      http: this.config.http,
    });
    this.stepUpClients.set(normalizedIssuer, client);
    return client;
  }

  private getCustomerProfileClientForIssuer(issuer: string): CustomerProfileClient {
    const normalizedIssuer = this.assertAllowedIssuer(issuer);
    const existing = this.customerProfileClients.get(normalizedIssuer);
    if (existing) {
      return existing;
    }
    const client = new CustomerProfileClient({
      issuer: normalizedIssuer,
      http: this.config.http,
    });
    this.customerProfileClients.set(normalizedIssuer, client);
    return client;
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
    tokenTypeHint?: TokenTypeHint,
    options?: AuthrimServerIssuerOptions
  ): Promise<IntrospectionResponse> {
    await this.init();

    return this.getIntrospectionClientForIssuer(this.resolveIssuer(options)).introspect({
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
    tokenTypeHint?: TokenTypeHint,
    options?: AuthrimServerIssuerOptions
  ): Promise<void> {
    await this.init();

    return this.getRevocationClientForIssuer(this.resolveIssuer(options)).revoke({
      token,
      token_type_hint: tokenTypeHint,
    });
  }

  /**
   * Introspect a Native SSO device_secret.
   *
   * Callers should avoid logging the raw device_secret.
   */
  async introspectDeviceSecret(
    deviceSecret: string,
    options?: AuthrimServerIssuerOptions
  ): Promise<IntrospectionResponse> {
    return this.introspect(deviceSecret, 'device_secret', options);
  }

  /**
   * Revoke a Native SSO device_secret.
   *
   * Callers should avoid logging the raw device_secret.
   */
  async revokeDeviceSecret(
    deviceSecret: string,
    options?: AuthrimServerIssuerOptions
  ): Promise<void> {
    return this.revoke(deviceSecret, 'device_secret', options);
  }

  /**
   * Start a canonical Step-Up action from a step_up_token.
   */
  async startStepUp(
    request: StepUpStartRequest,
    options?: AuthrimServerStepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    await this.init();
    return this.getStepUpClientForIssuer(this.resolveIssuer(options)).start(request, options);
  }

  /**
   * Read the current Step-Up action status.
   */
  async getStepUpAction(
    actionId: string,
    options?: AuthrimServerStepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    await this.init();
    return this.getStepUpClientForIssuer(this.resolveIssuer(options)).getAction(actionId, options);
  }

  /**
   * Complete a Step-Up action.
   *
   * If no idempotency key is provided, the SDK generates one.
   */
  async completeStepUpAction<Input = unknown>(
    actionId: string,
    request: StepUpCompleteRequest<Input>,
    options?: AuthrimServerStepUpIdempotentRequestOptions
  ): Promise<StepUpActionResponse> {
    await this.init();
    return this.getStepUpClientForIssuer(this.resolveIssuer(options)).complete(actionId, request, options);
  }

  /**
   * Resend a Step-Up challenge for resend-capable methods.
   *
   * If no idempotency key is provided, the SDK generates one.
   */
  async resendStepUpAction(
    actionId: string,
    options?: AuthrimServerStepUpIdempotentRequestOptions
  ): Promise<StepUpResendResponse> {
    await this.init();
    return this.getStepUpClientForIssuer(this.resolveIssuer(options)).resend(actionId, options);
  }

  /**
   * Cancel a pending Step-Up action.
   */
  async cancelStepUpAction(
    actionId: string,
    options?: AuthrimServerStepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    await this.init();
    return this.getStepUpClientForIssuer(this.resolveIssuer(options)).cancel(actionId, options);
  }

  /**
   * Canonical Step-Up helper namespace.
   */
  get stepUp(): AuthrimServerStepUpNamespace {
    return {
      start: this.startStepUp.bind(this),
      getAction: this.getStepUpAction.bind(this),
      complete: this.completeStepUpAction.bind(this),
      resend: this.resendStepUpAction.bind(this),
      cancel: this.cancelStepUpAction.bind(this),
    };
  }

  get customerProfiles() {
    return {
      getWithElevationGrant: async (
        subjectUserId: string,
        options: CustomerProfileRequestOptions & AuthrimServerIssuerOptions
      ) => {
        await this.init();
        return this.getCustomerProfileClientForIssuer(
          this.resolveIssuer(options)
        ).getWithElevationGrant(subjectUserId, options);
      },
      updateDelegated: async (
        subjectUserId: string,
        input: CustomerProfileUpdateInput,
        options: CustomerProfileDelegatedWriteOptions & AuthrimServerIssuerOptions
      ) => {
        await this.init();
        return this.getCustomerProfileClientForIssuer(
          this.resolveIssuer(options)
        ).updateDelegated(subjectUserId, input, options);
      },
    };
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
    for (const manager of this.jwksManagers.values()) {
      manager.invalidate();
    }
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
