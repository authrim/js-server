/**
 * HTTP Error Response Utilities
 *
 * Helpers for building OAuth 2.0 / RFC 6750 compliant error responses.
 */

import { AuthrimServerError } from '../types/errors.js';

/**
 * OAuth 2.0 error response body
 */
export interface ErrorResponseBody {
  error: string;
  error_description?: string;
}

/**
 * Sanitize a string value for use in HTTP header quoted-string
 *
 * Per RFC 7230 Section 3.2.6, a quoted-string consists of:
 * - DQUOTE *( qdtext / quoted-pair ) DQUOTE
 * - qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 * - quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
 *
 * We escape backslash and double-quote, and remove control characters.
 * CRITICAL: Must remove CR (\r, 0x0D) and LF (\n, 0x0A) to prevent header injection.
 */
function sanitizeHeaderValue(value: string): string {
  return value
    // Remove ALL control characters except tab (0x09):
    // - 0x00-0x08: NUL through BS
    // - 0x0A-0x1F: LF (0x0A), VT (0x0B), FF (0x0C), CR (0x0D), SO through US
    // - 0x7F: DEL
    // Note: Tab (0x09) is allowed per RFC 7230
    .replace(/[\x00-\x08\x0A-\x1F\x7F]/g, '')
    // Escape backslash first
    .replace(/\\/g, '\\\\')
    // Escape double quotes
    .replace(/"/g, '\\"')
    // Limit length to prevent header size issues
    .substring(0, 256);
}

/**
 * Build an error response body from an AuthrimServerError
 *
 * @param error - The error to convert
 * @returns Error response body
 */
export function buildErrorResponse(error: AuthrimServerError): ErrorResponseBody {
  return {
    error: error.meta.wwwAuthenticateError ?? 'server_error',
    error_description: error.message,
  };
}

/**
 * Build WWW-Authenticate header value (RFC 6750)
 *
 * @param error - The error
 * @param realm - Optional realm value
 * @param scheme - Authentication scheme ('Bearer' or 'DPoP')
 * @returns WWW-Authenticate header value
 */
export function buildWwwAuthenticateHeader(
  error: AuthrimServerError,
  realm?: string,
  scheme: 'Bearer' | 'DPoP' = 'Bearer'
): string {
  const parts: string[] = [scheme];

  if (realm) {
    // Sanitize realm to prevent header injection
    parts.push(`realm="${sanitizeHeaderValue(realm)}"`);
  }

  const wwwError = error.meta.wwwAuthenticateError;
  if (wwwError) {
    // wwwError is from a controlled set, but sanitize for safety
    parts.push(`error="${sanitizeHeaderValue(wwwError)}"`);
    // Sanitize error message to prevent header injection
    parts.push(`error_description="${sanitizeHeaderValue(error.message)}"`);
  }

  return parts.join(', ');
}

/**
 * Build error headers for HTTP response
 *
 * @param error - The error
 * @param options - Options for header building
 * @returns Headers object
 */
export function buildErrorHeaders(
  error: AuthrimServerError,
  options: {
    realm?: string;
    scheme?: 'Bearer' | 'DPoP';
    dpopNonce?: string;
  } = {}
): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Add WWW-Authenticate for 401 errors
  if (error.meta.httpStatus === 401) {
    headers['WWW-Authenticate'] = buildWwwAuthenticateHeader(
      error,
      options.realm,
      options.scheme ?? 'Bearer'
    );
  }

  // Add DPoP-Nonce for nonce-required errors
  if (error.code === 'dpop_nonce_required' && options.dpopNonce) {
    headers['DPoP-Nonce'] = options.dpopNonce;
  }

  return headers;
}
