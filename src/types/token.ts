/**
 * Token-related Type Definitions
 */

import type { ValidatedToken } from './claims.js';

/**
 * Token validation options
 */
export interface TokenValidationOptions {
  /** Expected issuer(s) */
  issuer: string | string[];
  /** Expected audience(s) */
  audience: string | string[];
  /** Clock tolerance in seconds (default: 60) */
  clockToleranceSeconds?: number;
  /** Required scopes (if any) */
  requiredScopes?: string[];
  /** Whether to validate DPoP binding if cnf claim is present */
  validateDPoP?: boolean;
}

/**
 * Claims validation options
 */
export interface ClaimsValidationOptions {
  /** Expected issuer(s) */
  issuer: string | string[];
  /** Expected audience(s) */
  audience: string | string[];
  /** Clock tolerance in seconds */
  clockToleranceSeconds: number;
  /** Current timestamp (Unix seconds) */
  now: number;
  /**
   * Require exp claim to be present
   * Per OIDC Core 1.0 Section 3.1.3.7, ID Tokens MUST have exp claim
   * Default: false (for generic JWT validation)
   */
  requireExp?: boolean;
  /**
   * Require iat claim to be present
   * Per OIDC Core 1.0 Section 3.1.3.7, ID Tokens MUST have iat claim
   * Default: false (for generic JWT validation)
   */
  requireIat?: boolean;
}

/**
 * Claims validation result
 */
export interface ClaimsValidationResult {
  valid: boolean;
  error?: {
    code: string;
    message: string;
  };
}

/**
 * Token validation result (success case)
 */
export interface TokenValidationSuccess {
  data: ValidatedToken;
  error: null;
}

/**
 * Token validation result (error case)
 */
export interface TokenValidationError {
  data: null;
  error: {
    code: string;
    message: string;
  };
}

/**
 * Token validation result (discriminated union)
 */
export type TokenValidationResult = TokenValidationSuccess | TokenValidationError;

/**
 * Token introspection request (RFC 7662)
 */
export interface IntrospectionRequest {
  /** Token to introspect */
  token: string;
  /** Token type hint */
  token_type_hint?: 'access_token' | 'refresh_token';
}

/**
 * Token introspection response (RFC 7662)
 */
export interface IntrospectionResponse {
  /** Whether the token is active */
  active: boolean;
  /** Scope */
  scope?: string;
  /** Client ID */
  client_id?: string;
  /** Username */
  username?: string;
  /** Token type */
  token_type?: string;
  /** Expiration time */
  exp?: number;
  /** Issued at */
  iat?: number;
  /** Not before */
  nbf?: number;
  /** Subject */
  sub?: string;
  /** Audience */
  aud?: string | string[];
  /** Issuer */
  iss?: string;
  /** JWT ID */
  jti?: string;
  /** Confirmation (DPoP binding) */
  cnf?: { jkt?: string };
  /** Additional claims */
  [key: string]: unknown;
}

/**
 * Token revocation request (RFC 7009)
 */
export interface RevocationRequest {
  /** Token to revoke */
  token: string;
  /** Token type hint */
  token_type_hint?: 'access_token' | 'refresh_token';
}
