/**
 * Core Authentication Function (Framework-Agnostic)
 *
 * This function is the ONLY authentication logic.
 * Framework adapters are thin wrappers that:
 * 1. Extract headers/method/url from framework-specific request
 * 2. Call authenticateRequest()
 * 3. Attach result to framework-specific context
 *
 * Header normalization:
 * - All header names are normalized to lowercase internally
 * - If multiple Authorization headers exist, only the first is used
 * - DPoP header lookup is case-insensitive
 */

import type { AuthrimServer } from '../core/client.js';
import type { AuthenticateRequest, AuthenticateResult } from './types.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Get header value (case-insensitive)
 */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const lowerName = name.toLowerCase();

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName) {
      if (Array.isArray(value)) {
        return value[0];
      }
      return value;
    }
  }

  return undefined;
}

/**
 * Parse Authorization header
 *
 * @param header - Authorization header value
 * @returns Parsed token and type
 */
function parseAuthorizationHeader(
  header: string | undefined
): { scheme: 'Bearer' | 'DPoP'; token: string } | null {
  if (!header) {
    return null;
  }

  const parts = header.split(' ');
  if (parts.length !== 2) {
    return null;
  }

  const [scheme, token] = parts;
  if (!scheme || !token) {
    return null;
  }

  const normalizedScheme = scheme.toLowerCase();
  if (normalizedScheme === 'bearer') {
    return { scheme: 'Bearer', token };
  }
  if (normalizedScheme === 'dpop') {
    return { scheme: 'DPoP', token };
  }

  return null;
}

/**
 * Authenticate a request
 *
 * @param server - AuthrimServer instance
 * @param request - Framework-agnostic request
 * @returns Authentication result
 */
export async function authenticateRequest(
  server: AuthrimServer,
  request: AuthenticateRequest
): Promise<AuthenticateResult> {
  // Parse Authorization header
  const authHeader = getHeader(request.headers, 'Authorization');
  const parsed = parseAuthorizationHeader(authHeader);

  if (!parsed) {
    return {
      data: null,
      error: {
        code: 'invalid_token',
        message: 'Missing or invalid Authorization header',
        httpStatus: 401,
      },
    };
  }

  const { scheme, token } = parsed;

  // Validate token
  const validationResult = await server.validateToken(token);

  if (validationResult.error) {
    const errorMeta = new AuthrimServerError(
      validationResult.error.code as any,
      validationResult.error.message
    ).meta;

    return {
      data: null,
      error: {
        code: validationResult.error.code,
        message: validationResult.error.message,
        httpStatus: errorMeta.httpStatus,
      },
    };
  }

  const claims = validationResult.data;
  if (!claims) {
    return {
      data: null,
      error: {
        code: 'invalid_token',
        message: 'Token validation failed',
        httpStatus: 401,
      },
    };
  }

  // Check if token is DPoP-bound
  const hasDPoPBinding = claims.claims.cnf?.jkt !== undefined;

  // If using DPoP scheme or token has DPoP binding, validate DPoP proof
  if (scheme === 'DPoP' || hasDPoPBinding) {
    const dpopHeader = getHeader(request.headers, 'DPoP');

    if (!dpopHeader) {
      return {
        data: null,
        error: {
          code: 'dpop_proof_missing',
          message: 'DPoP proof required but not provided',
          httpStatus: 401,
        },
      };
    }

    const dpopResult = await server.validateDPoP(dpopHeader, {
      method: request.method,
      uri: request.url,
      accessToken: token,
      expectedThumbprint: claims.claims.cnf?.jkt,
    });

    if (!dpopResult.valid) {
      return {
        data: null,
        error: {
          code: dpopResult.errorCode ?? 'dpop_proof_invalid',
          message: dpopResult.errorMessage ?? 'Invalid DPoP proof',
          httpStatus: 401,
        },
      };
    }
  }

  return {
    data: {
      claims,
      tokenType: hasDPoPBinding ? 'DPoP' : 'Bearer',
    },
    error: null,
  };
}
