/**
 * Server-side token-handler helpers for BFF/cookie session integrations.
 *
 * These helpers redeem browser-produced one-time artifacts on the server. The
 * returned OAuth/OIDC token material must stay server-side and be converted into
 * an application cookie/session by the caller.
 */

import {
  AUTHRIM_CSRF_COOKIE_NAME,
  createDoubleSubmitCsrfToken,
  resolveSessionCookieAttributes,
  type SessionCookieAttributes,
} from './csrf.js';

export type AuthrimServerSessionProfile = 'cookie_session' | 'token_session';

export interface DirectAuthArtifactRedeemRequest {
  directAuthArtifact: string;
  codeVerifier: string;
  clientId: string;
}

export interface DirectAuthArtifactRedeemConfig {
  issuer: string;
  tokenEndpoint?: string;
  fetch?: typeof fetch;
}

export interface DirectAuthArtifactTokenResponse {
  access_token: string;
  token_type: 'Bearer' | 'DPoP' | string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  [key: string]: unknown;
}

export interface CookieDescriptor {
  name: string;
  value: string;
  attributes: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Lax' | 'None';
    path: string;
    maxAge?: number;
  };
}

export interface CookieSessionRecord {
  sessionId: string;
  cookieName: string;
  cookieValue: string;
  maxAge?: number;
}

export interface CookieSessionCreateInput {
  tokens: DirectAuthArtifactTokenResponse;
  profile: 'cookie_session';
}

export interface CookieSessionAdapterHooks {
  createSession(input: CookieSessionCreateInput): Promise<CookieSessionRecord> | CookieSessionRecord;
}

export interface EstablishCookieSessionOptions {
  requestOrigin: string;
  applicationOrigin: string;
  csrfSecret: string;
  csrfCookieName?: string;
  cookiePath?: string;
}

export interface EstablishedCookieSession {
  sessionId: string;
  sessionCookie: CookieDescriptor;
  csrfCookie: CookieDescriptor;
}

export interface RefreshTokenReuseDetectedContext {
  refreshToken?: string;
  sessionId?: string;
  deviceId?: string;
  error: unknown;
}

export interface HandleRefreshTokenReuseDetectionOptions extends RefreshTokenReuseDetectedContext {
  revokeRefreshTokenFamily?: (context: RefreshTokenReuseDetectedContext) => Promise<void> | void;
  revokeSession?: (context: RefreshTokenReuseDetectedContext) => Promise<void> | void;
  revokeDeviceSession?: (context: RefreshTokenReuseDetectedContext) => Promise<void> | void;
}

export interface RefreshTokenReuseHandlingResult {
  handled: boolean;
  revoked: {
    refreshTokenFamily: boolean;
    session: boolean;
    deviceSession: boolean;
  };
}

export async function redeemDirectAuthArtifact(
  config: DirectAuthArtifactRedeemConfig,
  request: DirectAuthArtifactRedeemRequest
): Promise<DirectAuthArtifactTokenResponse> {
  if (!request.directAuthArtifact) {
    throw new Error('directAuthArtifact is required');
  }
  if (!request.codeVerifier) {
    throw new Error('codeVerifier is required');
  }
  if (!request.clientId) {
    throw new Error('clientId is required');
  }

  const body = new URLSearchParams();
  body.set('grant_type', 'urn:authrim:params:oauth:grant-type:direct-auth-finish');
  body.set('direct_auth_artifact', request.directAuthArtifact);
  body.set('code_verifier', request.codeVerifier);
  body.set('client_id', request.clientId);

  const fetchImpl = config.fetch ?? fetch;
  const tokenEndpoint = `${config.issuer.replace(/\/$/, '')}${config.tokenEndpoint ?? '/token'}`;
  const response = await fetchImpl(tokenEndpoint, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  const data = (await response.json().catch(() => ({}))) as Partial<DirectAuthArtifactTokenResponse> & {
    error?: string;
    error_description?: string;
  };

  if (!response.ok || typeof data.access_token !== 'string') {
    throw new Error(data.error_description ?? data.error ?? 'direct_auth_artifact_redeem_failed');
  }

  return data as DirectAuthArtifactTokenResponse;
}

export async function establishCookieSessionFromDirectAuthArtifact(
  config: DirectAuthArtifactRedeemConfig,
  request: DirectAuthArtifactRedeemRequest,
  hooks: CookieSessionAdapterHooks,
  options: EstablishCookieSessionOptions
): Promise<EstablishedCookieSession> {
  const tokens = await redeemDirectAuthArtifact(config, request);
  const record = await hooks.createSession({
    tokens,
    profile: 'cookie_session',
  });
  const csrfToken = await createDoubleSubmitCsrfToken({
    secret: options.csrfSecret,
    sessionId: record.sessionId,
  });
  const cookieAttributes = resolveSessionCookieAttributes({
    requestOrigin: options.requestOrigin,
    applicationOrigin: options.applicationOrigin,
  });
  const path = options.cookiePath ?? '/';

  return {
    sessionId: record.sessionId,
    sessionCookie: {
      name: record.cookieName,
      value: record.cookieValue,
      attributes: {
        ...cookieAttributes,
        path,
        maxAge: record.maxAge,
      },
    },
    csrfCookie: {
      name: options.csrfCookieName ?? AUTHRIM_CSRF_COOKIE_NAME,
      value: csrfToken,
      attributes: {
        ...csrfCookieAttributes(cookieAttributes),
        path,
        maxAge: record.maxAge,
      },
    },
  };
}

export async function handleRefreshTokenReuseDetection(
  options: HandleRefreshTokenReuseDetectionOptions
): Promise<RefreshTokenReuseHandlingResult> {
  if (!isRefreshTokenReuseDetected(options.error)) {
    return {
      handled: false,
      revoked: {
        refreshTokenFamily: false,
        session: false,
        deviceSession: false,
      },
    };
  }

  const context: RefreshTokenReuseDetectedContext = {
    refreshToken: options.refreshToken,
    sessionId: options.sessionId,
    deviceId: options.deviceId,
    error: options.error,
  };
  const revoked = {
    refreshTokenFamily: false,
    session: false,
    deviceSession: false,
  };

  if (options.revokeRefreshTokenFamily) {
    await options.revokeRefreshTokenFamily(context);
    revoked.refreshTokenFamily = true;
  }
  if (options.revokeSession) {
    await options.revokeSession(context);
    revoked.session = true;
  }
  if (options.revokeDeviceSession) {
    await options.revokeDeviceSession(context);
    revoked.deviceSession = true;
  }

  return {
    handled: true,
    revoked,
  };
}

export function isRefreshTokenReuseDetected(error: unknown): boolean {
  if (!error) {
    return false;
  }
  if (typeof error === 'string') {
    return error === 'refresh_token_reuse_detected';
  }
  if (typeof error !== 'object') {
    return false;
  }
  const maybeError = error as {
    code?: unknown;
    error?: unknown;
    details?: { originalError?: unknown };
  };
  return (
    maybeError.code === 'refresh_token_reuse_detected' ||
    maybeError.error === 'refresh_token_reuse_detected' ||
    maybeError.details?.originalError === 'refresh_token_reuse_detected'
  );
}

function csrfCookieAttributes(
  sessionCookieAttributes: SessionCookieAttributes
): Omit<CookieDescriptor['attributes'], 'path' | 'maxAge'> {
  return {
    httpOnly: false,
    secure: sessionCookieAttributes.secure,
    sameSite: sessionCookieAttributes.sameSite,
  };
}
