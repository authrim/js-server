/**
 * Koa Adapter
 *
 * Thin wrapper around authenticateRequest for Koa framework.
 */

import type { AuthrimServer } from '../core/client.js';
import type { MiddlewareOptions } from '../middleware/types.js';
import type { ValidatedToken } from '../types/claims.js';
import { authenticateRequest } from '../middleware/authenticate.js';
import { buildErrorResponse, buildErrorHeaders } from '../utils/error-response.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Koa state with auth
 */
export interface AuthrimKoaState {
  auth?: ValidatedToken;
  authTokenType?: 'Bearer' | 'DPoP';
}

/**
 * Koa context type (minimal interface)
 */
interface KoaContext {
  request: {
    headers: Record<string, string | string[] | undefined>;
    method: string;
    protocol: string;
    host: string;
    url: string;
  };
  response: {
    status: number;
    set(headers: Record<string, string>): void;
    body: unknown;
  };
  state: AuthrimKoaState;
}

/**
 * Koa next function
 */
type KoaNext = () => Promise<void>;

/**
 * Create Koa middleware for token validation
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Koa middleware function
 *
 * @example
 * ```typescript
 * import Koa from 'koa';
 * import { createAuthrimServer } from '@authrim/server';
 * import { authrimMiddleware } from '@authrim/server/adapters/koa';
 *
 * const app = new Koa();
 * const server = createAuthrimServer({
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 * });
 *
 * app.use(authrimMiddleware(server));
 *
 * app.use((ctx) => {
 *   ctx.body = { user: ctx.state.auth?.claims.sub };
 * });
 * ```
 */
export function authrimMiddleware(
  server: AuthrimServer,
  options: MiddlewareOptions = {}
) {
  return async (ctx: KoaContext, next: KoaNext): Promise<void> => {
    // Build URL
    const url = `${ctx.request.protocol}://${ctx.request.host}${ctx.request.url}`;

    // Authenticate
    const result = await authenticateRequest(server, {
      headers: ctx.request.headers as Record<string, string | string[] | undefined>,
      method: ctx.request.method,
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

      ctx.response.status = result.error.httpStatus;
      ctx.response.set(headers);
      ctx.response.body = buildErrorResponse(error);
      return;
    }

    // Attach auth to state
    ctx.state.auth = result.data.claims;
    ctx.state.authTokenType = result.data.tokenType;

    await next();
  };
}

/**
 * Create optional auth middleware (doesn't fail if no token)
 *
 * @param server - AuthrimServer instance
 * @param _options - Middleware options (unused for optional middleware)
 * @returns Koa middleware function
 */
export function authrimOptionalMiddleware(
  server: AuthrimServer,
  _options: MiddlewareOptions = {}
) {
  return async (ctx: KoaContext, next: KoaNext): Promise<void> => {
    // Check if Authorization header exists
    const authHeader = ctx.request.headers['authorization'];
    if (!authHeader) {
      await next();
      return;
    }

    // Build URL
    const url = `${ctx.request.protocol}://${ctx.request.host}${ctx.request.url}`;

    // Authenticate
    const result = await authenticateRequest(server, {
      headers: ctx.request.headers as Record<string, string | string[] | undefined>,
      method: ctx.request.method,
      url,
    });

    if (result.data) {
      ctx.state.auth = result.data.claims;
      ctx.state.authTokenType = result.data.tokenType;
    }

    await next();
  };
}
