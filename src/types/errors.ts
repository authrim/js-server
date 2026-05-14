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
  | 'invalid_tenant'
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
  | 'invalid_cursor'
  | 'unknown_audit_field'
  | 'revoke_disabled'
  | 'introspection_disabled'
  | 'unauthorized_introspection_caller'
  // Step-Up / delegated write errors
  | 'step_up_required'
  | 'preferred_method_unavailable'
  | 'invalid_step_up_input'
  | 'step_up_attempts_exhausted'
  | 'resend_limit_exceeded'
  | 'user_canceled'
  | 'idempotency_conflict'
  // Compatibility errors
  | 'legacy_app_suite_not_supported'
  | 'legacy_native_sso_discovery_unsupported'
  | 'legacy_endpoint_not_supported'
  | 'legacy_passkey_error_unsupported'
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
  /** Error severity for SDK classification */
  severity?: 'fatal' | 'error' | 'warning';
}

export type StepUpActionStatus = 'pending' | 'completed' | 'failed' | 'expired' | 'canceled';

export interface StepUpInputState {
  field?: string;
  attempts_remaining?: number;
  max_attempts?: number;
  retry_after_seconds?: number;
  [key: string]: unknown;
}

export interface StepUpPreferredMethod {
  category?: string;
  method?: string;
}

export interface StepUpStatusObject {
  action_id?: string;
  status: StepUpActionStatus;
  method?: string;
  category?: string;
  preferred_method?: StepUpPreferredMethod;
  attempts_remaining?: number;
  max_attempts?: number;
  resend_available_at?: string;
  resend_available_at_unix?: number;
  resends_remaining?: number;
  expires_at?: string;
  expires_at_unix?: number;
  updated_at?: string;
  updated_at_unix?: number;
  [key: string]: unknown;
}

export type StepUpErrorDetailCode =
  | 'step_up_required'
  | 'preferred_method_unavailable'
  | 'invalid_step_up_input'
  | 'step_up_attempts_exhausted'
  | 'resend_limit_exceeded'
  | 'user_canceled'
  | 'idempotency_conflict';

export interface Phase1ErrorDetails<Code extends string = string> {
  code: Code;
  retryable: boolean;
  severity: 'warning' | 'error' | 'fatal';
  user_action?: 'retry' | 'reauthenticate' | 'update_client' | 'contact_support' | 'none';
  transient?: boolean;
  field?: string;
  input_state?: StepUpInputState;
  [key: string]: unknown;
}

export interface StepUpErrorResponseBody {
  error: string;
  error_description?: string;
  error_details: Phase1ErrorDetails<StepUpErrorDetailCode>;
  step_up?: unknown;
  status?: StepUpStatusObject;
  input_state?: StepUpInputState;
  next_action?: unknown;
}

/**
 * Options for creating an AuthrimServerError
 */
export interface AuthrimServerErrorOptions {
  details?: Record<string, unknown>;
  errorUri?: string;
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

  /** OAuth error_uri if provided */
  readonly errorUri?: string;

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
    this.errorUri = options?.errorUri;
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
  invalid_tenant: {
    httpStatus: 403,
    transient: false,
    retryable: false,
    wwwAuthenticateError: 'insufficient_scope',
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
  invalid_cursor: {
    httpStatus: 400,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  unknown_audit_field: {
    httpStatus: 400,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  revoke_disabled: {
    httpStatus: 403,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  introspection_disabled: {
    httpStatus: 403,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  unauthorized_introspection_caller: {
    httpStatus: 403,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  step_up_required: {
    httpStatus: 403,
    transient: false,
    retryable: false,
    severity: 'warning',
  },
  preferred_method_unavailable: {
    httpStatus: 403,
    transient: false,
    retryable: true,
    severity: 'warning',
  },
  invalid_step_up_input: {
    httpStatus: 400,
    transient: false,
    retryable: true,
    severity: 'warning',
  },
  step_up_attempts_exhausted: {
    httpStatus: 409,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  resend_limit_exceeded: {
    httpStatus: 429,
    transient: false,
    retryable: false,
    severity: 'warning',
  },
  user_canceled: {
    httpStatus: 409,
    transient: false,
    retryable: true,
    severity: 'warning',
  },
  idempotency_conflict: {
    httpStatus: 409,
    transient: false,
    retryable: false,
    severity: 'error',
  },
  legacy_app_suite_not_supported: {
    httpStatus: 400,
    transient: false,
    retryable: false,
    severity: 'fatal',
  },
  legacy_native_sso_discovery_unsupported: {
    httpStatus: 400,
    transient: false,
    retryable: false,
    severity: 'fatal',
  },
  legacy_endpoint_not_supported: {
    httpStatus: 400,
    transient: false,
    retryable: false,
    severity: 'fatal',
  },
  legacy_passkey_error_unsupported: {
    httpStatus: 400,
    transient: false,
    retryable: false,
    severity: 'fatal',
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

/**
 * Check whether a raw error string is one of Authrim's machine-readable server SDK codes.
 */
export function isAuthrimServerErrorCode(code: string): code is AuthrimServerErrorCode {
  return Object.prototype.hasOwnProperty.call(ERROR_META_MAP, code);
}

/**
 * OAuth-style error payload returned by Authrim endpoints.
 */
export interface AuthrimOAuthErrorResponse {
  error?: unknown;
  error_description?: unknown;
  error_uri?: unknown;
  error_details?: Phase1ErrorDetails | unknown;
  status?: StepUpStatusObject | unknown;
  input_state?: StepUpInputState | unknown;
}

/**
 * Preserve Authrim machine-readable errors from endpoint error payloads.
 */
export function createServerErrorFromOAuthResponse(
  payload: AuthrimOAuthErrorResponse | null | undefined,
  fallbackCode: AuthrimServerErrorCode,
  fallbackMessage: string,
  details?: Record<string, unknown>
): AuthrimServerError {
  const rawCode = typeof payload?.error === 'string' ? payload.error : undefined;
  const code =
    rawCode && isAuthrimServerErrorCode(rawCode) ? rawCode : fallbackCode;
  const description =
    typeof payload?.error_description === 'string'
      ? payload.error_description
      : fallbackMessage;
  const errorUri = typeof payload?.error_uri === 'string' ? payload.error_uri : undefined;

  return new AuthrimServerError(code, description, {
    errorUri,
    details: {
      ...details,
      originalError: rawCode,
      errorDetails: payload?.error_details,
      status: payload?.status,
      inputState: payload?.input_state,
    },
  });
}
