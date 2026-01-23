/**
 * Fastify Adapter
 *
 * Thin wrapper around authenticateRequest for Fastify framework.
 */

import type { AuthrimServer } from '../core/client.js';
import type { MiddlewareOptions } from '../middleware/types.js';
import type { ValidatedToken } from '../types/claims.js';
import { authenticateRequest } from '../middleware/authenticate.js';
import { buildErrorResponse, buildErrorHeaders } from '../utils/error-response.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Extended Fastify Request with auth property
 *
 * Note: Users should add this to their own type declarations:
 * declare module 'fastify' {
 *   interface FastifyRequest {
 *     auth?: ValidatedToken;
 *     authTokenType?: 'Bearer' | 'DPoP';
 *   }
 * }
 */

/**
 * Fastify request type (minimal interface)
 */
interface FastifyRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  protocol: string;
  hostname: string;
  url: string;
}

/**
 * Fastify reply type (minimal interface)
 */
interface FastifyReply {
  code(statusCode: number): FastifyReply;
  headers(headers: Record<string, string>): FastifyReply;
  send(payload?: unknown): FastifyReply;
}

/**
 * Create Fastify preHandler hook for token validation
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Fastify preHandler function
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { createAuthrimServer } from '@authrim/server';
 * import { authrimPreHandler } from '@authrim/server/adapters/fastify';
 *
 * const fastify = Fastify();
 * const server = createAuthrimServer({
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 * });
 *
 * fastify.addHook('preHandler', authrimPreHandler(server));
 *
 * fastify.get('/api/protected', async (request) => {
 *   return { user: request.auth.claims.sub };
 * });
 * ```
 */
export function authrimPreHandler(
  server: AuthrimServer,
  options: MiddlewareOptions = {}
) {
  return async (
    request: FastifyRequest & { auth?: ValidatedToken; authTokenType?: 'Bearer' | 'DPoP' },
    reply: FastifyReply
  ): Promise<void> => {
    // Build URL
    const url = `${request.protocol}://${request.hostname}${request.url}`;

    // Authenticate
    const result = await authenticateRequest(server, {
      headers: request.headers as Record<string, string | string[] | undefined>,
      method: request.method,
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

      reply.code(result.error.httpStatus).headers(headers).send(buildErrorResponse(error));
      return;
    }

    // Attach auth to request
    request.auth = result.data.claims;
    request.authTokenType = result.data.tokenType;
  };
}

/**
 * Create optional auth preHandler (doesn't fail if no token)
 *
 * @param server - AuthrimServer instance
 * @param _options - Middleware options (unused for optional middleware)
 * @returns Fastify preHandler function
 */
export function authrimOptionalPreHandler(
  server: AuthrimServer,
  _options: MiddlewareOptions = {}
) {
  return async (
    request: FastifyRequest & { auth?: ValidatedToken; authTokenType?: 'Bearer' | 'DPoP' },
    _reply: FastifyReply
  ): Promise<void> => {
    // Check if Authorization header exists
    const authHeader = request.headers['authorization'];
    if (!authHeader) {
      return;
    }

    // Build URL
    const url = `${request.protocol}://${request.hostname}${request.url}`;

    // Authenticate
    const result = await authenticateRequest(server, {
      headers: request.headers as Record<string, string | string[] | undefined>,
      method: request.method,
      url,
    });

    if (result.data) {
      request.auth = result.data.claims;
      request.authTokenType = result.data.tokenType;
    }
  };
}

/**
 * Create Fastify plugin for token validation
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Fastify plugin
 */
export function authrimPlugin(server: AuthrimServer, options: MiddlewareOptions = {}) {
  return async (fastify: { addHook: (name: string, handler: unknown) => void }) => {
    fastify.addHook('preHandler', authrimPreHandler(server, options));
  };
}

/**
 * Create optional Fastify plugin (doesn't fail if no token)
 *
 * @param server - AuthrimServer instance
 * @param options - Middleware options
 * @returns Fastify plugin
 */
export function authrimOptionalPlugin(server: AuthrimServer, options: MiddlewareOptions = {}) {
  return async (fastify: { addHook: (name: string, handler: unknown) => void }) => {
    fastify.addHook('preHandler', authrimOptionalPreHandler(server, options));
  };
}
