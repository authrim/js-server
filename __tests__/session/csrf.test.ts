import { describe, expect, it } from 'vitest';
import {
  createDoubleSubmitCsrfToken,
  resolveSessionCookieAttributes,
  verifyCookieSessionRequestHeaders,
  verifyCookieSessionRequestOrigin,
  verifyDoubleSubmitCsrfToken,
} from '../../src/session/csrf.js';

describe('signed double-submit CSRF helpers', () => {
  it('creates and verifies a token bound to the session id', async () => {
    const token = await createDoubleSubmitCsrfToken({
      secret: 'csrf-secret',
      sessionId: 'session-123',
      random: 'random-token',
    });

    await expect(
      verifyDoubleSubmitCsrfToken({
        secret: 'csrf-secret',
        sessionId: 'session-123',
        cookieToken: token,
        headerToken: token,
      })
    ).resolves.toEqual({ ok: true });
  });

  it('rejects missing, mismatched, and wrong-session tokens', async () => {
    const token = await createDoubleSubmitCsrfToken({
      secret: 'csrf-secret',
      sessionId: 'session-123',
      random: 'random-token',
    });

    await expect(
      verifyDoubleSubmitCsrfToken({
        secret: 'csrf-secret',
        sessionId: 'session-123',
        cookieToken: token,
      })
    ).resolves.toEqual({ ok: false, error: 'missing_csrf_token' });

    await expect(
      verifyDoubleSubmitCsrfToken({
        secret: 'csrf-secret',
        sessionId: 'session-123',
        cookieToken: token,
        headerToken: `${token}-changed`,
      })
    ).resolves.toEqual({ ok: false, error: 'csrf_token_mismatch' });

    await expect(
      verifyDoubleSubmitCsrfToken({
        secret: 'csrf-secret',
        sessionId: 'session-other',
        cookieToken: token,
        headerToken: token,
      })
    ).resolves.toEqual({ ok: false, error: 'csrf_token_invalid' });
  });
});

describe('cookie session origin helpers', () => {
  it('accepts allowed Origin and falls back to Referer when Origin is absent', () => {
    expect(
      verifyCookieSessionRequestOrigin({
        origin: 'https://app.example.test/path',
        allowedOrigins: ['https://app.example.test'],
      })
    ).toEqual({ ok: true, origin: 'https://app.example.test', source: 'origin' });

    expect(
      verifyCookieSessionRequestOrigin({
        referer: 'https://app.example.test/account/settings',
        allowedOrigins: ['https://app.example.test'],
      })
    ).toEqual({ ok: true, origin: 'https://app.example.test', source: 'referer' });
  });

  it('rejects missing, invalid, and untrusted request origins', () => {
    expect(
      verifyCookieSessionRequestOrigin({
        allowedOrigins: ['https://app.example.test'],
      })
    ).toEqual({ ok: false, error: 'missing_request_origin' });

    expect(
      verifyCookieSessionRequestOrigin({
        origin: 'null',
        allowedOrigins: ['https://app.example.test'],
      })
    ).toEqual({ ok: false, error: 'invalid_request_origin' });

    expect(
      verifyCookieSessionRequestOrigin({
        origin: 'https://evil.example.test',
        allowedOrigins: ['https://app.example.test'],
      })
    ).toEqual({ ok: false, error: 'request_origin_not_allowed' });
  });

  it('verifies Fetch Headers and resolves cookie attributes by origin mode', () => {
    const headers = new Headers({
      Origin: 'https://rp.example.test',
    });

    expect(verifyCookieSessionRequestHeaders(headers, ['https://rp.example.test'])).toEqual({
      ok: true,
      origin: 'https://rp.example.test',
      source: 'origin',
    });

    expect(
      resolveSessionCookieAttributes({
        requestOrigin: 'https://rp.example.test',
        applicationOrigin: 'https://rp.example.test',
      })
    ).toEqual({ httpOnly: true, secure: true, sameSite: 'Lax' });

    expect(
      resolveSessionCookieAttributes({
        requestOrigin: 'https://rp.example.test',
        applicationOrigin: 'https://auth.example.test',
      })
    ).toEqual({ httpOnly: true, secure: true, sameSite: 'None' });
  });
});
