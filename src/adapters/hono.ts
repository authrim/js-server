/**
 * Hono Adapter
 *
 * Thin wrapper around authenticateRequest for Hono framework.
 */

import type { AuthrimServer } from '../core/client.js';
import type { MiddlewareOptions } from '../middleware/types.js';
import type { ValidatedToken } from '../types/claims.js';
import { authenticateRequest } from '../middleware/authenticate.js';
import { buildErrorResponse, buildErrorHeaders } from '../utils/error-response.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Hono context variable key for auth
 */
export const AUTH_KEY = 'auth';
export const AUTH_TOKEN_TYPE_KEY = 'authTokenType';

/**
 * Hono Context type (minimal interface)
 */
interface HonoContext {
  req: {
    header(name: string): string | undefined;
    method: string;
    url: string;
    raw: Request;
  };
  set(key: string, value: unknown): void;
  get(key: string): unknown;
  json(data: unknown, status?: number): Response;
  header(name: string, value: string): void;
}

/**
 * Hono next function
 */
type HonoNext = () => Promise<void>;

/**
 * Get auth from Hono context
 *
 * @param c - Hono context
 * @returns Validated token or undefined
 */
export function getAuth(c: HonoContext): ValidatedToken | undefined {
  return c.get(AUTH_KEY) as ValidatedToken | undefined;
}

/**
 * Get auth token type from Hono context
 *
 * @param c - Hono context
 * @returns Token type or undefined
 */
export function getAuthTokenType(c: HonoContext): 'Bearer' | 'DPoP' | undefined {
  return c.get(AUTH_TOKEN_TYPE_KEY) as 'Bearer' | 'DPoP' | undefined;
}

/**
 * Create Hono middleware for token validation
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Hono middleware function
 *
 * @example
 * ```typescript
 * import { Hono } from 'hono';
 * import { createAuthrimServer } from '@authrim/server';
 * import { authrimMiddleware, getAuth } from '@authrim/server/adapters/hono';
 *
 * const app = new Hono();
 * const server = createAuthrimServer({
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 * });
 *
 * app.use('/api/*', authrimMiddleware(server));
 *
 * app.get('/api/protected', (c) => {
 *   const auth = getAuth(c);
 *   return c.json({ user: auth?.claims.sub });
 * });
 * ```
 */
export function authrimMiddleware(
  server: AuthrimServer,
  options: MiddlewareOptions = {}
) {
  return async (c: HonoContext, next: HonoNext): Promise<Response | void> => {
    // Build headers record
    const headers: Record<string, string> = {};
    const rawHeaders = c.req.raw.headers;
    rawHeaders.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    // Authenticate
    const result = await authenticateRequest(server, {
      headers,
      method: c.req.method,
      url: c.req.url,
    });

    if (result.error) {
      const error = new AuthrimServerError(
        result.error.code as any,
        result.error.message
      );

      const errorHeaders = buildErrorHeaders(error, {
        realm: options.realm,
        scheme: 'Bearer',
      });

      if (options.onError) {
        options.onError(result.error);
      }

      for (const [key, value] of Object.entries(errorHeaders)) {
        c.header(key, value);
      }

      return c.json(buildErrorResponse(error), result.error.httpStatus);
    }

    // Set auth in context
    c.set(AUTH_KEY, result.data.claims);
    c.set(AUTH_TOKEN_TYPE_KEY, result.data.tokenType);

    await next();
  };
}

/**
 * Create optional auth middleware (doesn't fail if no token)
 *
 * @param server - AuthrimServer instance
 * @param _options - Middleware options (unused for optional middleware)
 * @returns Hono middleware function
 */
export function authrimOptionalMiddleware(
  server: AuthrimServer,
  _options: MiddlewareOptions = {}
) {
  return async (c: HonoContext, next: HonoNext): Promise<void> => {
    // Check if Authorization header exists
    const authHeader = c.req.header('authorization');
    if (!authHeader) {
      await next();
      return;
    }

    // Build headers record
    const headers: Record<string, string> = {};
    const rawHeaders = c.req.raw.headers;
    rawHeaders.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    // Authenticate
    const result = await authenticateRequest(server, {
      headers,
      method: c.req.method,
      url: c.req.url,
    });

    if (result.data) {
      c.set(AUTH_KEY, result.data.claims);
      c.set(AUTH_TOKEN_TYPE_KEY, result.data.tokenType);
    }

    await next();
  };
}
