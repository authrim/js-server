/**
 * Authrim Server SDK Error Types
 *
 * These error codes are specific to server-side token validation and DPoP operations.
 */

/**
 * Server SDK error codes
 */
export type AuthrimServerErrorCode =
  // JWT validation errors
  | 'invalid_token'
  | 'token_expired'
  | 'token_not_yet_valid'
  | 'token_malformed'
  | 'signature_invalid'
  | 'algorithm_mismatch'
  // Issuer/Audience validation
  | 'invalid_issuer'
  | 'invalid_audience'
  // JWKS errors
  | 'jwks_fetch_error'
  | 'jwks_key_not_found'
  | 'jwks_key_ambiguous'
  | 'jwks_key_import_error'
  // DPoP errors
  | 'dpop_proof_missing'
  | 'dpop_proof_invalid'
  | 'dpop_proof_signature_invalid'
  | 'dpop_method_mismatch'
  | 'dpop_uri_mismatch'
  | 'dpop_ath_mismatch'
  | 'dpop_binding_mismatch'
  | 'dpop_iat_expired'
  | 'dpop_nonce_required'
  // Token introspection/revocation errors
  | 'introspection_error'
  | 'revocation_error'
  // Configuration errors
  | 'configuration_error'
  | 'provider_error'
  // Network errors
  | 'network_error'
  | 'timeout_error';

/**
 * Error metadata for recovery information
 */
export interface AuthrimServerErrorMeta {
  /** HTTP status code to return */
  httpStatus: number;
  /** Whether this is a transient error */
  transient: boolean;
  /** Whether automatic retry is possible */
  retryable: boolean;
  /** WWW-Authenticate error attribute */
  wwwAuthenticateError?: string;
}

/**
 * Options for creating an AuthrimServerError
 */
export interface AuthrimServerErrorOptions {
  details?: Record<string, unknown>;
  cause?: Error;
}

/**
 * Authrim Server SDK Error class
 */
export class AuthrimServerError extends Error {
  /** Error code for programmatic handling */
  readonly code: AuthrimServerErrorCode;

  /** Additional error details */
  readonly details?: Record<string, unknown>;

  /** Underlying cause */
  readonly cause?: Error;

  constructor(
    code: AuthrimServerErrorCode,
    message: string,
    options?: AuthrimServerErrorOptions
  ) {
    super(message);
    this.name = 'AuthrimServerError';
    this.code = code;
    this.details = options?.details;
    this.cause = options?.cause;
  }

  /**
   * Get error metadata for HTTP response
   */
  get meta(): AuthrimServerErrorMeta {
    return getServerErrorMeta(this.code);
  }
}

/**
 * Error metadata mapping for each error code
 */
const ERROR_META_MAP: Record<AuthrimServerErrorCode, AuthrimServerErrorMeta> = {
  // JWT validation errors
  invalid_token: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  token_expired: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  token_not_yet_valid: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  token_malformed: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  signature_invalid: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  algorithm_mismatch: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },

  // Issuer/Audience validation
  invalid_issuer: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  invalid_audience: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },

  // JWKS errors
  jwks_fetch_error: {
    httpStatus: 503,
    transient: true,
    retryable: true,
  },
  jwks_key_not_found: {
    httpStatus: 401,
    transient: true,
    retryable: true,
    wwwAuthenticateError: 'invalid_token',
  },
  jwks_key_ambiguous: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  jwks_key_import_error: {
    httpStatus: 500,
    transient: false,
    retryable: false,
  },

  // DPoP errors
  dpop_proof_missing: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_proof_invalid: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_proof_signature_invalid: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_method_mismatch: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_uri_mismatch: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_ath_mismatch: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_binding_mismatch: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_iat_expired: {
    httpStatus: 401,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'invalid_token',
  },
  dpop_nonce_required: {
    httpStatus: 401,
    transient: true,
    retryable: true,
    wwwAuthenticateError: 'use_dpop_nonce',
  },

  // Token introspection/revocation errors
  introspection_error: {
    httpStatus: 503,
    transient: true,
    retryable: true,
  },
  revocation_error: {
    httpStatus: 503,
    transient: true,
    retryable: true,
  },

  // Configuration errors
  configuration_error: {
    httpStatus: 500,
    transient: false,
    retryable: false,
  },
  provider_error: {
    httpStatus: 500,
    transient: false,
    retryable: false,
  },

  // Network errors
  network_error: {
    httpStatus: 503,
    transient: true,
    retryable: true,
  },
  timeout_error: {
    httpStatus: 504,
    transient: true,
    retryable: true,
  },
};

/**
 * Get error metadata for a given error code
 */
export function getServerErrorMeta(code: AuthrimServerErrorCode): AuthrimServerErrorMeta {
  return ERROR_META_MAP[code];
}
