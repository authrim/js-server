/**
 * Session Management Type Definitions
 *
 * OpenID Connect Back-Channel Logout 1.0
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 */

/**
 * Logout token claims (for back-channel logout)
 *
 * Per OIDC Back-Channel Logout 1.0 Section 2.4, the logout token MUST contain:
 * - iss: Issuer Identifier
 * - aud: Audience (one or more)
 * - iat: Issued At
 * - exp: Expiration Time
 * - jti: JWT ID (unique identifier)
 * - events: MUST contain "http://schemas.openid.net/event/backchannel-logout" key
 * - sub and/or sid: At least one MUST be present
 *
 * The logout token MUST NOT contain:
 * - nonce claim (to prevent confusion with ID tokens)
 */
export interface LogoutTokenClaims {
  /** Issuer */
  iss: string;
  /** Subject (optional, but either sub or sid must be present) */
  sub?: string;
  /** Audience (one or more client_ids) */
  aud: string | string[];
  /** Issued at time (Unix timestamp) */
  iat: number;
  /** Expiration time (Unix timestamp) - REQUIRED per Section 2.4 */
  exp: number;
  /** JWT ID (unique identifier for replay protection) */
  jti: string;
  /**
   * Events claim
   * MUST contain the back-channel logout event with an empty object value
   */
  events: {
    'http://schemas.openid.net/event/backchannel-logout': Record<string, never>;
  };
  /** Session ID (optional, but either sub or sid must be present) */
  sid?: string;
}
