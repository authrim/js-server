/**
 * Session Module
 *
 * OpenID Connect Back-Channel Logout 1.0
 */

export {
  BackChannelLogoutValidator,
  BACKCHANNEL_LOGOUT_EVENT,
  type BackChannelLogoutErrorCode,
  type BackChannelLogoutValidationOptions,
  type BackChannelLogoutValidationResult,
} from './back-channel-logout.js';
export {
  establishCookieSessionFromDirectAuthArtifact,
  handleRefreshTokenReuseDetection,
  isRefreshTokenReuseDetected,
  redeemDirectAuthArtifact,
  type AuthrimServerSessionProfile,
  type CookieDescriptor,
  type CookieSessionAdapterHooks,
  type CookieSessionCreateInput,
  type CookieSessionRecord,
  type DirectAuthArtifactRedeemConfig,
  type DirectAuthArtifactRedeemRequest,
  type DirectAuthArtifactTokenResponse,
  type EstablishedCookieSession,
  type EstablishCookieSessionOptions,
  type HandleRefreshTokenReuseDetectionOptions,
  type RefreshTokenReuseDetectedContext,
  type RefreshTokenReuseHandlingResult,
} from './token-handler.js';
export {
  AUTHRIM_CSRF_COOKIE_NAME,
  AUTHRIM_CSRF_HEADER_NAME,
  createDoubleSubmitCsrfToken,
  resolveSessionCookieAttributes,
  verifyDoubleSubmitCsrfToken,
  verifyCookieSessionRequestHeaders,
  verifyCookieSessionRequestOrigin,
  type CookieSessionRequestOriginValidationResult,
  type CreateDoubleSubmitCsrfTokenOptions,
  type DoubleSubmitCsrfValidationResult,
  type ResolveSessionCookieAttributesOptions,
  type SessionCookieAttributes,
  type VerifyCookieSessionRequestOriginOptions,
  type VerifyDoubleSubmitCsrfTokenOptions,
} from './csrf.js';
