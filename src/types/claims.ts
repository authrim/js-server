/**
 * JWT Claims Type Definitions
 *
 * Based on RFC 7519 (JSON Web Token) and OIDC Core 1.0
 */

/**
 * Standard JWT claims (RFC 7519 Section 4.1)
 */
export interface StandardClaims {
  /** Issuer */
  iss?: string;
  /** Subject */
  sub?: string;
  /** Audience (string or array) */
  aud?: string | string[];
  /** Expiration Time (Unix timestamp) */
  exp?: number;
  /** Not Before (Unix timestamp) */
  nbf?: number;
  /** Issued At (Unix timestamp) */
  iat?: number;
  /** JWT ID */
  jti?: string;
}

/**
 * DPoP confirmation claim (RFC 9449)
 */
export interface ConfirmationClaim {
  /** JWK Thumbprint (RFC 7638) */
  jkt?: string;
}

/**
 * Access token claims
 */
export interface AccessTokenClaims extends StandardClaims {
  /** Client ID */
  client_id?: string;
  /** Scope (space-separated string) */
  scope?: string;
  /** Token ID (for introspection reference) */
  token_id?: string;
  /** Confirmation claim (for DPoP-bound tokens) */
  cnf?: ConfirmationClaim;
  /** Allow additional custom claims */
  [key: string]: unknown;
}

/**
 * ID token claims (OIDC Core 1.0)
 */
export interface IdTokenClaims extends StandardClaims {
  /** Nonce */
  nonce?: string;
  /** Authentication time */
  auth_time?: number;
  /** Access token hash */
  at_hash?: string;
  /** Code hash */
  c_hash?: string;
  /** ACR (Authentication Context Class Reference) */
  acr?: string;
  /** AMR (Authentication Methods References) */
  amr?: string[];
  /** Authorized party */
  azp?: string;
  /** Allow additional custom claims */
  [key: string]: unknown;
}

/**
 * Validated token result
 */
export interface ValidatedToken {
  /** Parsed and validated claims */
  claims: AccessTokenClaims;
  /** Raw token string */
  token: string;
  /** Token type */
  tokenType: 'Bearer' | 'DPoP';
  /** Time remaining until expiration (seconds) */
  expiresIn?: number;
}

/**
 * JWT header (RFC 7519 Section 5)
 */
export interface JwtHeader {
  /** Algorithm */
  alg: string;
  /** Type (should be 'JWT') */
  typ?: string;
  /** Key ID */
  kid?: string;
  /** JWK (for DPoP proofs) */
  jwk?: Record<string, unknown>;
}

/**
 * Parsed JWT structure
 */
export interface ParsedJwt<T = Record<string, unknown>> {
  header: JwtHeader;
  payload: T;
  signature: string;
}
