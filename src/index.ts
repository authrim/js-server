/**
 * @authrim/server
 *
 * Server SDK for token validation, DPoP support, and framework middleware.
 *
 * This SDK uses `jose` as the reference JOSE implementation.
 * Other language SDKs may use different libraries (e.g., Nimbus for Java,
 * go-jose for Go, Microsoft.IdentityModel for .NET) as long as the same
 * verification steps are followed.
 */

// Main client
export { AuthrimServer, createAuthrimServer } from './core/client.js';

// Types
export type {
  AuthrimServerConfig,
  ResolvedAuthrimServerConfig,
  MemoryCacheOptions,
} from './types/config.js';
export type {
  AuthrimServerErrorCode,
  AuthrimServerErrorOptions,
  AuthrimServerErrorMeta,
} from './types/errors.js';
export { AuthrimServerError, getServerErrorMeta } from './types/errors.js';
export type {
  PublicJwk,
  RsaPublicJwk,
  EcPublicJwk,
  OkpPublicJwk,
  JwkSet,
  JwkKeyType,
  JwkKeyUse,
  JwkSigningAlgorithm,
} from './types/jwk.js';
export type {
  StandardClaims,
  AccessTokenClaims,
  IdTokenClaims,
  ValidatedToken,
  JwtHeader,
  ParsedJwt,
  ConfirmationClaim,
} from './types/claims.js';
export type {
  DPoPProofHeader,
  DPoPProofPayload,
  DPoPValidationOptions,
  DPoPValidationResult,
} from './types/dpop.js';
export type {
  TokenValidationOptions,
  TokenValidationResult,
  ClaimsValidationOptions,
  ClaimsValidationResult,
  IntrospectionRequest,
  IntrospectionResponse,
  RevocationRequest,
} from './types/token.js';
export type { LogoutTokenClaims } from './types/session.js';

// Middleware
export { authenticateRequest } from './middleware/authenticate.js';
export type {
  AuthenticateRequest,
  AuthenticateResult,
  AuthenticateSuccess,
  AuthenticateError,
  MiddlewareOptions,
} from './middleware/types.js';

// JWKS
export { JwksManager, type JwksManagerConfig, type KeyImportWarning } from './jwks/manager.js';
export { selectKey, selectKeyByKid, selectKeyByAlgorithm } from './jwks/key-selector.js';

// Token
export { parseJwt, verifyJwtSignature } from './token/verify-jwt.js';
export { validateClaims, getExpiresIn } from './token/validate-claims.js';
export { TokenValidator, type TokenValidatorConfig } from './token/validator.js';
export { IntrospectionClient, type IntrospectionClientConfig } from './token/introspection.js';
export { RevocationClient, type RevocationClientConfig } from './token/revocation.js';

// DPoP
export { DPoPValidator } from './dpop/validator.js';
export { calculateJwkThumbprint, verifyJwkThumbprint } from './dpop/thumbprint.js';

// Utils
export {
  base64UrlEncode,
  base64UrlDecode,
  base64UrlEncodeString,
  base64UrlDecodeString,
} from './utils/base64url.js';
export { buildErrorResponse, buildWwwAuthenticateHeader, buildErrorHeaders } from './utils/error-response.js';

// Session
export {
  BackChannelLogoutValidator,
  BACKCHANNEL_LOGOUT_EVENT,
  type BackChannelLogoutErrorCode,
  type BackChannelLogoutValidationOptions,
  type BackChannelLogoutValidationResult,
} from './session/index.js';
