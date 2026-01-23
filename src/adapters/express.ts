/**
 * Express Adapter
 *
 * Thin wrapper around authenticateRequest for Express framework.
 */

import type { AuthrimServer } from '../core/client.js';
import type { MiddlewareOptions } from '../middleware/types.js';
import type { ValidatedToken } from '../types/claims.js';
import { authenticateRequest } from '../middleware/authenticate.js';
import { buildErrorResponse, buildErrorHeaders } from '../utils/error-response.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Extended Express Request with auth property
 */
export interface AuthrimExpressRequest {
  auth?: ValidatedToken;
  authTokenType?: 'Bearer' | 'DPoP';
}

/**
 * Express request type (minimal interface)
 */
interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  protocol: string;
  get(name: string): string | undefined;
  originalUrl: string;
}

/**
 * Express response type (minimal interface)
 */
interface ExpressResponse {
  status(code: number): ExpressResponse;
  set(headers: Record<string, string>): ExpressResponse;
  json(body: unknown): void;
}

/**
 * Express next function
 */
type ExpressNextFunction = (err?: unknown) => void;

/**
 * Create Express middleware for token validation
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createAuthrimServer } from '@authrim/server';
 * import { authrimMiddleware } from '@authrim/server/adapters/express';
 *
 * const app = express();
 * const server = createAuthrimServer({
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 * });
 *
 * app.use('/api', authrimMiddleware(server));
 *
 * app.get('/api/protected', (req, res) => {
 *   res.json({ user: req.auth.claims.sub });
 * });
 * ```
 */
export function authrimMiddleware(
  server: AuthrimServer,
  options: MiddlewareOptions = {}
) {
  return async (
    req: ExpressRequest & AuthrimExpressRequest,
    res: ExpressResponse,
    next: ExpressNextFunction
  ): Promise<void> => {
    // Build URL
    const host = req.get('host') ?? 'localhost';
    const url = `${req.protocol}://${host}${req.originalUrl}`;

    // Authenticate
    const result = await authenticateRequest(server, {
      headers: req.headers as Record<string, string | string[] | undefined>,
      method: req.method,
      url,
    });

    if (result.error) {
      const error = new AuthrimServerError(
        result.error.code as any,
        result.error.message
      );

      const headers = buildErrorHeaders(error, {
        realm: options.realm,
        scheme: 'Bearer',
      });

      if (options.onError) {
        options.onError(result.error);
      }

      res.status(result.error.httpStatus).set(headers).json(buildErrorResponse(error));
      return;
    }

    // Attach auth to request
    req.auth = result.data.claims;
    req.authTokenType = result.data.tokenType;

    next();
  };
}

/**
 * Create optional auth middleware (doesn't fail if no token)
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Express middleware function
 */
export function authrimOptionalMiddleware(
  server: AuthrimServer,
  _options: MiddlewareOptions = {}
) {
  return async (
    req: ExpressRequest & AuthrimExpressRequest,
    _res: ExpressResponse,
    next: ExpressNextFunction
  ): Promise<void> => {
    // Check if Authorization header exists
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      next();
      return;
    }

    // Build URL
    const host = req.get('host') ?? 'localhost';
    const url = `${req.protocol}://${host}${req.originalUrl}`;

    // Authenticate
    const result = await authenticateRequest(server, {
      headers: req.headers as Record<string, string | string[] | undefined>,
      method: req.method,
      url,
    });

    if (result.data) {
      req.auth = result.data.claims;
      req.authTokenType = result.data.tokenType;
    }

    next();
  };
}
