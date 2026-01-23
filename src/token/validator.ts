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

/**
 * Token Validator configuration
 */
export interface TokenValidatorConfig {
  /** JWKS Manager */
  jwksManager: JwksManager;
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

      // Get signing key from JWKS
      const keyResult = await this.config.jwksManager.getKey(parsed.header);
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

      // Determine token type
      const tokenType = verified.payload.cnf?.jkt ? 'DPoP' : 'Bearer';

      // Build validated token
      const validatedToken: ValidatedToken = {
        claims: verified.payload,
        token,
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
