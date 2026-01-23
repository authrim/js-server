/**
 * Middleware Type Definitions
 */

import type { ValidatedToken } from '../types/claims.js';

/**
 * Framework-agnostic request representation
 */
export interface AuthenticateRequest {
  /** HTTP headers (keys should be lowercase) */
  headers: Record<string, string | string[] | undefined>;
  /** HTTP method */
  method: string;
  /** Full URL (scheme://host:port/path) */
  url: string;
}

/**
 * Authentication result (success case)
 */
export interface AuthenticateSuccess {
  data: {
    /** Validated token claims */
    claims: ValidatedToken;
    /** Token type */
    tokenType: 'Bearer' | 'DPoP';
  };
  error: null;
}

/**
 * Authentication result (error case)
 */
export interface AuthenticateError {
  data: null;
  error: {
    code: string;
    message: string;
    httpStatus: number;
  };
}

/**
 * Authentication result (discriminated union)
 */
export type AuthenticateResult = AuthenticateSuccess | AuthenticateError;

/**
 * Middleware options
 */
export interface MiddlewareOptions {
  /** Optional realm for WWW-Authenticate header */
  realm?: string;
  /** Required scopes (optional) */
  requiredScopes?: string[];
  /** Whether to validate DPoP binding */
  validateDPoP?: boolean;
  /** Custom error handler */
  onError?: (error: AuthenticateError['error']) => void;
}
