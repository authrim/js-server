/**
 * Middleware
 */

export { authenticateRequest } from './authenticate.js';
export type {
  AuthenticateRequest,
  AuthenticateResult,
  AuthenticateSuccess,
  AuthenticateError,
  MiddlewareOptions,
} from './types.js';
