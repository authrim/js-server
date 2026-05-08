import { timingSafeEqual } from '../utils/timing-safe.js';

export const AUTHRIM_CSRF_COOKIE_NAME = 'authrim_csrf';
export const AUTHRIM_CSRF_HEADER_NAME = 'x-authrim-csrf';

export interface CreateDoubleSubmitCsrfTokenOptions {
  secret: string;
  sessionId: string;
  random?: string;
}

export interface VerifyDoubleSubmitCsrfTokenOptions {
  secret: string;
  sessionId: string;
  cookieToken?: string | null;
  headerToken?: string | null;
}

export type DoubleSubmitCsrfValidationResult =
  | { ok: true }
  | { ok: false; error: 'missing_csrf_token' | 'csrf_token_mismatch' | 'csrf_token_invalid' };

export interface VerifyCookieSessionRequestOriginOptions {
  origin?: string | null;
  referer?: string | null;
  allowedOrigins: readonly string[];
}

export type CookieSessionRequestOriginValidationResult =
  | { ok: true; origin: string; source: 'origin' | 'referer' }
  | { ok: false; error: 'missing_request_origin' | 'invalid_request_origin' | 'request_origin_not_allowed' };

export interface ResolveSessionCookieAttributesOptions {
  requestOrigin: string;
  applicationOrigin: string;
}

export interface SessionCookieAttributes {
  httpOnly: true;
  secure: boolean;
  sameSite: 'Lax' | 'None';
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function generateRandomToken(byteLength = 32): string {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new Error('Web Crypto getRandomValues is required to create CSRF tokens');
  }

  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

async function sign(secret: string, message: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto subtle is required to sign CSRF tokens');
  }

  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return base64urlEncode(new Uint8Array(signature));
}

export async function createDoubleSubmitCsrfToken(
  options: CreateDoubleSubmitCsrfTokenOptions
): Promise<string> {
  const random = options.random ?? generateRandomToken();
  const signature = await sign(options.secret, `${options.sessionId}.${random}`);
  return `v1.${random}.${signature}`;
}

export async function verifyDoubleSubmitCsrfToken(
  options: VerifyDoubleSubmitCsrfTokenOptions
): Promise<DoubleSubmitCsrfValidationResult> {
  const cookieToken = options.cookieToken ?? '';
  const headerToken = options.headerToken ?? '';

  if (!cookieToken || !headerToken) {
    return { ok: false, error: 'missing_csrf_token' };
  }

  if (!timingSafeEqual(cookieToken, headerToken)) {
    return { ok: false, error: 'csrf_token_mismatch' };
  }

  const [version, random, signature] = cookieToken.split('.');
  if (version !== 'v1' || !random || !signature) {
    return { ok: false, error: 'csrf_token_invalid' };
  }

  const expected = await createDoubleSubmitCsrfToken({
    secret: options.secret,
    sessionId: options.sessionId,
    random,
  });

  return timingSafeEqual(cookieToken, expected)
    ? { ok: true }
    : { ok: false, error: 'csrf_token_invalid' };
}

export function verifyCookieSessionRequestOrigin(
  options: VerifyCookieSessionRequestOriginOptions
): CookieSessionRequestOriginValidationResult {
  const origin = normalizeOrigin(options.origin);
  const refererOrigin = normalizeRefererOrigin(options.referer);

  if (options.origin && !origin) {
    return { ok: false, error: 'invalid_request_origin' };
  }

  if (!origin && options.referer && !refererOrigin) {
    return { ok: false, error: 'invalid_request_origin' };
  }

  const requestOrigin = origin ?? refererOrigin;

  if (!requestOrigin) {
    return { ok: false, error: 'missing_request_origin' };
  }

  const allowedOrigins = new Set(
    options.allowedOrigins
      .map((allowedOrigin) => normalizeOrigin(allowedOrigin))
      .filter((allowedOrigin): allowedOrigin is string => Boolean(allowedOrigin))
  );

  if (allowedOrigins.size === 0) {
    return { ok: false, error: 'request_origin_not_allowed' };
  }

  if (!allowedOrigins.has(requestOrigin)) {
    return { ok: false, error: 'request_origin_not_allowed' };
  }

  return {
    ok: true,
    origin: requestOrigin,
    source: origin ? 'origin' : 'referer',
  };
}

export function verifyCookieSessionRequestHeaders(
  headers: Headers,
  allowedOrigins: readonly string[]
): CookieSessionRequestOriginValidationResult {
  return verifyCookieSessionRequestOrigin({
    origin: headers.get('origin'),
    referer: headers.get('referer'),
    allowedOrigins,
  });
}

export function resolveSessionCookieAttributes(
  options: ResolveSessionCookieAttributesOptions
): SessionCookieAttributes {
  const requestOrigin = normalizeOrigin(options.requestOrigin);
  const applicationOrigin = normalizeOrigin(options.applicationOrigin);
  const crossOrigin = Boolean(requestOrigin && applicationOrigin && requestOrigin !== applicationOrigin);

  return {
    httpOnly: true,
    secure: crossOrigin || applicationOrigin?.startsWith('https://') === true,
    sameSite: crossOrigin ? 'None' : 'Lax',
  };
}

function normalizeRefererOrigin(referer?: string | null): string | null {
  if (!referer) {
    return null;
  }

  try {
    return new URL(referer).origin;
  } catch {
    return null;
  }
}

function normalizeOrigin(origin?: string | null): string | null {
  if (!origin) {
    return null;
  }

  try {
    return new URL(origin).origin;
  } catch {
    return null;
  }
}
