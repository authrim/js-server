/**
 * NestJS Adapter
 *
 * Guard and decorator for NestJS applications.
 */

import type { AuthrimServer } from '../core/client.js';
import type { MiddlewareOptions } from '../middleware/types.js';
import type { ValidatedToken } from '../types/claims.js';
import { authenticateRequest } from '../middleware/authenticate.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * NestJS ExecutionContext type (minimal interface)
 */
interface ExecutionContext {
  switchToHttp(): {
    getRequest(): {
      headers: Record<string, string | string[] | undefined>;
      method: string;
      protocol: string;
      get(name: string): string | undefined;
      originalUrl: string;
      auth?: ValidatedToken;
      authTokenType?: 'Bearer' | 'DPoP';
    };
  };
}

/**
 * NestJS CanActivate interface (minimal)
 */
interface CanActivate {
  canActivate(context: ExecutionContext): Promise<boolean>;
}

/**
 * NestJS HttpException (minimal interface)
 */
interface HttpExceptionConstructor {
  new (response: object, status: number): Error;
}

/**
 * Create NestJS guard factory for token validation
 *
 * @param server - AuthrimServer instance
 * @param httpException - HttpException class from @nestjs/common
 * @param options - Middleware options
 * @returns NestJS Guard class
 *
 * @example
 * ```typescript
 * import { Controller, Get, UseGuards } from '@nestjs/common';
 * import { HttpException } from '@nestjs/common';
 * import { createAuthrimServer } from '@authrim/server';
 * import { createAuthrimGuard, Auth } from '@authrim/server/adapters/nestjs';
 *
 * const server = createAuthrimServer({
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 * });
 *
 * const AuthrimGuard = createAuthrimGuard(server, HttpException);
 *
 * @Controller('api')
 * export class AppController {
 *   @Get('protected')
 *   @UseGuards(AuthrimGuard)
 *   getProtected(@Auth() auth: ValidatedToken) {
 *     return { user: auth.claims.sub };
 *   }
 * }
 * ```
 */
export function createAuthrimGuard(
  server: AuthrimServer,
  HttpException: HttpExceptionConstructor,
  options: MiddlewareOptions = {}
): new () => CanActivate {
  return class AuthrimGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const httpContext = context.switchToHttp();
      const request = httpContext.getRequest();

      // Build URL
      const host = request.get('host') ?? 'localhost';
      const url = `${request.protocol}://${host}${request.originalUrl}`;

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

        if (options.onError) {
          options.onError(result.error);
        }

        throw new HttpException(
          {
            statusCode: result.error.httpStatus,
            error: error.meta.wwwAuthenticateError ?? 'Unauthorized',
            message: result.error.message,
          },
          result.error.httpStatus
        );
      }

      // Attach auth to request
      request.auth = result.data.claims;
      request.authTokenType = result.data.tokenType;

      return true;
    }
  };
}

/**
 * Parameter decorator factory for extracting auth from request
 *
 * Note: This is a minimal implementation. For full NestJS decorator support,
 * you'll need to use @nestjs/common's createParamDecorator.
 *
 * @example
 * ```typescript
 * import { createParamDecorator, ExecutionContext } from '@nestjs/common';
 * import { getAuthFromRequest } from '@authrim/server/adapters/nestjs';
 *
 * export const Auth = createParamDecorator(
 *   (data: unknown, ctx: ExecutionContext) => {
 *     return getAuthFromRequest(ctx);
 *   }
 * );
 * ```
 */
export function getAuthFromRequest(context: ExecutionContext): ValidatedToken | undefined {
  const request = context.switchToHttp().getRequest();
  return request.auth;
}

/**
 * Get auth token type from request
 */
export function getAuthTokenTypeFromRequest(
  context: ExecutionContext
): 'Bearer' | 'DPoP' | undefined {
  const request = context.switchToHttp().getRequest();
  return request.authTokenType;
}

/**
 * Create optional NestJS guard factory (doesn't fail if no token)
 *
 * @param server - AuthrimServer instance
 * @param _options - Middleware options (unused for optional guard)
 * @returns NestJS Guard class that always allows access
 *
 * @example
 * ```typescript
 * import { Controller, Get, UseGuards } from '@nestjs/common';
 * import { createAuthrimServer } from '@authrim/server';
 * import { createAuthrimOptionalGuard, Auth } from '@authrim/server/adapters/nestjs';
 *
 * const server = createAuthrimServer({
 *   issuer: 'https://auth.example.com',
 *   audience: 'https://api.example.com',
 * });
 *
 * const AuthrimOptionalGuard = createAuthrimOptionalGuard(server);
 *
 * @Controller('api')
 * export class AppController {
 *   @Get('public')
 *   @UseGuards(AuthrimOptionalGuard)
 *   getPublic(@Auth() auth: ValidatedToken | undefined) {
 *     return { user: auth?.claims.sub ?? 'anonymous' };
 *   }
 * }
 * ```
 */
export function createAuthrimOptionalGuard(
  server: AuthrimServer,
  _options: MiddlewareOptions = {}
): new () => CanActivate {
  return class AuthrimOptionalGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const httpContext = context.switchToHttp();
      const request = httpContext.getRequest();

      // Check if Authorization header exists
      const authHeader = request.headers['authorization'];
      if (!authHeader) {
        return true;
      }

      // Build URL
      const host = request.get('host') ?? 'localhost';
      const url = `${request.protocol}://${host}${request.originalUrl}`;

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

      // Always allow access for optional guard
      return true;
    }
  };
}
