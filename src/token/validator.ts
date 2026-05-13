/**
 * Token Validator
 *
 * Orchestrates JWT signature verification and claims validation.
 */

import type { CryptoProvider } from '../providers/crypto.js';
import type { ClockProvider } from '../providers/clock.js';
import type { AccessTokenClaims, ValidatedToken } from '../types/claims.js';
import type { TokenValidationOptions, TokenValidationResult } from '../types/token.js';
import { AuthrimServerError } from '../types/errors.js';
import { JwksManager } from '../jwks/manager.js';
import { parseJwt, verifyJwtSignature } from './verify-jwt.js';
import { validateClaims, getExpiresIn } from './validate-claims.js';
import { timingSafeEqual } from '../utils/timing-safe.js';

/**
 * Token Validator configuration
 */
export interface TokenValidatorConfig {
  /** JWKS Manager. Used when all configured issuers share the same JWKS. */
  jwksManager?: JwksManager;
  /** Resolve the JWKS manager for the token issuer. */
  jwksManagerResolver?: (issuer: string) => Promise<JwksManager>;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Clock provider */
  clock: ClockProvider;
  /** Validation options */
  options: TokenValidationOptions;
}

/**
 * Token Validator
 *
 * Combines JWKS key retrieval, signature verification, and claims validation.
 */
export class TokenValidator {
  private readonly config: TokenValidatorConfig;

  constructor(config: TokenValidatorConfig) {
    this.config = config;
  }

  /**
   * Validate a JWT access token
   *
   * Steps:
   * 1. Parse JWT structure
   * 2. Get signing key from JWKS
   * 3. Verify signature
   * 4. Validate claims (iss, aud, exp, nbf, iat)
   *
   * @param token - JWT string
   * @returns Validation result
   */
  async validate(token: string): Promise<TokenValidationResult> {
    try {
      // Parse JWT to get header
      let parsed;
      try {
        parsed = parseJwt<AccessTokenClaims>(token);
      } catch (error) {
        return {
          data: null,
          error: {
            code: 'token_malformed',
            message: error instanceof Error ? error.message : 'Invalid JWT format',
          },
        };
      }

      const issuerResult = this.validateUnverifiedIssuer(parsed.payload.iss);
      if (!issuerResult.valid) {
        return {
          data: null,
          error: issuerResult.error,
        };
      }

      const tokenIssuer = parsed.payload.iss!;

      // Get signing key from the JWKS allowed for this issuer.
      const jwksManager = await this.getJwksManager(tokenIssuer);
      const keyResult = await jwksManager.getKey(parsed.header);
      if (keyResult.error) {
        return {
          data: null,
          error: {
            code: keyResult.error.code,
            message: keyResult.error.message,
          },
        };
      }

      if (!keyResult.key) {
        return {
          data: null,
          error: {
            code: 'jwks_key_not_found',
            message: 'No suitable key found in JWKS',
          },
        };
      }

      // Verify signature
      const verified = await verifyJwtSignature<AccessTokenClaims>(
        token,
        keyResult.key.cryptoKey,
        this.config.crypto
      );

      if (!verified) {
        return {
          data: null,
          error: {
            code: 'signature_invalid',
            message: 'JWT signature verification failed',
          },
        };
      }

      // Validate claims
      const now = this.config.clock.nowSeconds();
      const claimsResult = validateClaims(verified.payload, {
        issuer: this.config.options.issuer,
        audience: this.config.options.audience,
        clockToleranceSeconds: this.config.options.clockToleranceSeconds ?? 60,
        now,
      });

      if (!claimsResult.valid && claimsResult.error) {
        return {
          data: null,
          error: claimsResult.error,
        };
      }

      // Validate required scopes if specified
      if (this.config.options.requiredScopes?.length) {
        const scopeResult = this.validateScopes(
          verified.payload.scope,
          this.config.options.requiredScopes
        );
        if (!scopeResult.valid && scopeResult.error) {
          return {
            data: null,
            error: scopeResult.error,
          };
        }
      }

      const tenantResult = await this.validateTenant(verified.payload);
      if (!tenantResult.valid && tenantResult.error) {
        return {
          data: null,
          error: tenantResult.error,
        };
      }
      const tenantId = tenantResult.valid ? tenantResult.tenantId : undefined;

      // Determine token type
      const tokenType = verified.payload.cnf?.jkt ? 'DPoP' : 'Bearer';

      // Build validated token
      const validatedToken: ValidatedToken = {
        claims: verified.payload,
        token,
        issuer: tokenIssuer,
        ...(tenantId ? { tenantId } : {}),
        tokenType,
        expiresIn: getExpiresIn(verified.payload.exp, now),
      };

      return {
        data: validatedToken,
        error: null,
      };
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        return {
          data: null,
          error: {
            code: error.code,
            message: error.message,
          },
        };
      }

      return {
        data: null,
        error: {
          code: 'invalid_token',
          message: error instanceof Error ? error.message : 'Token validation failed',
        },
      };
    }
  }

  /**
   * Resolve JWKS manager for the already allow-listed issuer.
   */
  private async getJwksManager(issuer: string): Promise<JwksManager> {
    if (this.config.jwksManagerResolver) {
      return this.config.jwksManagerResolver(issuer);
    }
    if (this.config.jwksManager) {
      return this.config.jwksManager;
    }
    throw new AuthrimServerError('configuration_error', 'JWKS manager not configured');
  }

  /**
   * Validate issuer before any JWKS lookup to avoid attacker-controlled discovery.
   */
  private validateUnverifiedIssuer(
    iss: string | undefined
  ): { valid: true } | { valid: false; error: { code: string; message: string } } {
    if (!iss) {
      return {
        valid: false,
        error: { code: 'invalid_issuer', message: 'Missing or empty issuer claim' },
      };
    }

    const expected = Array.isArray(this.config.options.issuer)
      ? this.config.options.issuer
      : [this.config.options.issuer];
    const validIssuers = expected.filter((issuer) => issuer !== '');
    if (validIssuers.length === 0) {
      return {
        valid: false,
        error: { code: 'invalid_issuer', message: 'No valid expected issuers configured' },
      };
    }

    if (!validIssuers.some((issuer) => timingSafeEqual(iss, issuer))) {
      return {
        valid: false,
        error: { code: 'invalid_issuer', message: `Invalid issuer: ${iss}` },
      };
    }

    return { valid: true };
  }

  /**
   * Validate tenant claim according to SDK caller policy.
   */
  private async validateTenant(
    claims: AccessTokenClaims
  ): Promise<
    | { valid: true; tenantId?: string }
    | { valid: false; error: { code: string; message: string } }
  > {
    const claimName = this.config.options.tenantClaim ?? 'tenant_id';
    const rawTenantId = claims[claimName];
    const tenantId = typeof rawTenantId === 'string' && rawTenantId.trim() ? rawTenantId : undefined;
    const hasTenantRule =
      this.config.options.requireTenantClaim === true ||
      Boolean(this.config.options.requiredTenantId) ||
      Boolean(this.config.options.allowedTenantIds?.length) ||
      Boolean(this.config.options.tenantPredicate);

    if (!tenantId) {
      if (!hasTenantRule) {
        return { valid: true };
      }
      return {
        valid: false,
        error: {
          code: 'invalid_tenant',
          message: `Missing or empty tenant claim: ${claimName}`,
        },
      };
    }

    if (
      this.config.options.requiredTenantId &&
      !timingSafeEqual(tenantId, this.config.options.requiredTenantId)
    ) {
      return {
        valid: false,
        error: { code: 'invalid_tenant', message: 'Token tenant does not match required tenant' },
      };
    }

    if (
      this.config.options.allowedTenantIds?.length &&
      !this.config.options.allowedTenantIds.some((allowed) => timingSafeEqual(tenantId, allowed))
    ) {
      return {
        valid: false,
        error: { code: 'invalid_tenant', message: 'Token tenant is not allowed' },
      };
    }

    if (this.config.options.tenantPredicate) {
      const allowed = await this.config.options.tenantPredicate(tenantId, claims);
      if (!allowed) {
        return {
          valid: false,
          error: { code: 'invalid_tenant', message: 'Token tenant was rejected by predicate' },
        };
      }
    }

    return { valid: true, tenantId };
  }

  /**
   * Validate required scopes
   */
  private validateScopes(
    tokenScope: string | undefined,
    requiredScopes: string[]
  ): { valid: boolean; error?: { code: string; message: string } } {
    if (!tokenScope) {
      return {
        valid: false,
        error: {
          code: 'insufficient_scope',
          message: `Missing required scopes: ${requiredScopes.join(' ')}`,
        },
      };
    }

    const tokenScopes = tokenScope.split(' ');
    const missingScopes = requiredScopes.filter((s) => !tokenScopes.includes(s));

    if (missingScopes.length > 0) {
      return {
        valid: false,
        error: {
          code: 'insufficient_scope',
          message: `Missing required scopes: ${missingScopes.join(' ')}`,
        },
      };
    }

    return { valid: true };
  }
}
