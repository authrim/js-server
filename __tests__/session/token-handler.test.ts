import { describe, expect, it, vi } from 'vitest';

import {
  establishCookieSessionFromDirectAuthArtifact,
  handleRefreshTokenReuseDetection,
  isRefreshTokenReuseDetected,
  redeemDirectAuthArtifact,
} from '../../src/session/token-handler.js';

describe('server token-handler helpers', () => {
  it('redeems Direct Auth artifacts through the canonical token grant', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'server-access-token',
          token_type: 'Bearer',
          expires_in: 300,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    );

    const token = await redeemDirectAuthArtifact(
      {
        issuer: 'https://auth.example.com',
        fetch: fetchMock,
      },
      {
        directAuthArtifact: 'artifact-123',
        codeVerifier: 'verifier-123',
        clientId: 'rp-server',
      }
    );

    expect(token.access_token).toBe('server-access-token');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://auth.example.com/token');
    expect(init?.method).toBe('POST');
    const body = init?.body as URLSearchParams;
    expect(body.get('grant_type')).toBe('urn:authrim:params:oauth:grant-type:direct-auth-finish');
    expect(body.get('direct_auth_artifact')).toBe('artifact-123');
    expect(body.get('code_verifier')).toBe('verifier-123');
    expect(body.get('client_id')).toBe('rp-server');
  });

  it('throws without returning token material on failed redeem', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: 'invalid_grant',
          error_description: 'Artifact expired',
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    );

    await expect(
      redeemDirectAuthArtifact(
        {
          issuer: 'https://auth.example.com',
          fetch: fetchMock,
        },
        {
          directAuthArtifact: 'artifact-123',
          codeVerifier: 'verifier-123',
          clientId: 'rp-server',
        }
      )
    ).rejects.toThrow('Artifact expired');
  });

  it('establishes a cookie session without returning OAuth token material', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'server-access-token',
          refresh_token: 'server-refresh-token',
          token_type: 'Bearer',
          expires_in: 300,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    );
    const createSession = vi.fn().mockResolvedValue({
      sessionId: 'session-123',
      cookieName: 'app_session',
      cookieValue: 'opaque-session-id',
      maxAge: 300,
    });

    const result = await establishCookieSessionFromDirectAuthArtifact(
      {
        issuer: 'https://auth.example.com',
        fetch: fetchMock,
      },
      {
        directAuthArtifact: 'artifact-123',
        codeVerifier: 'verifier-123',
        clientId: 'rp-server',
      },
      { createSession },
      {
        requestOrigin: 'https://app.example.com',
        applicationOrigin: 'https://auth.example.com',
        csrfSecret: 'csrf-secret',
      }
    );

    expect(createSession).toHaveBeenCalledWith({
      profile: 'cookie_session',
      tokens: expect.objectContaining({
        access_token: 'server-access-token',
        refresh_token: 'server-refresh-token',
      }),
    });
    expect(result).toMatchObject({
      sessionId: 'session-123',
      sessionCookie: {
        name: 'app_session',
        value: 'opaque-session-id',
        attributes: {
          httpOnly: true,
          secure: true,
          sameSite: 'None',
          path: '/',
          maxAge: 300,
        },
      },
      csrfCookie: {
        name: 'authrim_csrf',
        attributes: {
          httpOnly: false,
          secure: true,
          sameSite: 'None',
          path: '/',
          maxAge: 300,
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain('server-access-token');
    expect(JSON.stringify(result)).not.toContain('server-refresh-token');
  });

  it('runs refresh-token-reuse revocation hooks for the token family and session', async () => {
    const revokeRefreshTokenFamily = vi.fn();
    const revokeSession = vi.fn();
    const revokeDeviceSession = vi.fn();
    const error = {
      code: 'refresh_token_reuse_detected',
      message: 'Refresh token reuse detected',
    };

    const result = await handleRefreshTokenReuseDetection({
      error,
      refreshToken: 'refresh-token',
      sessionId: 'session-123',
      deviceId: 'device-123',
      revokeRefreshTokenFamily,
      revokeSession,
      revokeDeviceSession,
    });

    expect(result).toEqual({
      handled: true,
      revoked: {
        refreshTokenFamily: true,
        session: true,
        deviceSession: true,
      },
    });
    expect(revokeRefreshTokenFamily).toHaveBeenCalledWith(
      expect.objectContaining({
        refreshToken: 'refresh-token',
        sessionId: 'session-123',
        deviceId: 'device-123',
      })
    );
    expect(revokeSession).toHaveBeenCalledWith(expect.objectContaining({ sessionId: 'session-123' }));
    expect(revokeDeviceSession).toHaveBeenCalledWith(expect.objectContaining({ deviceId: 'device-123' }));
  });

  it('does not run reuse revocation hooks for unrelated refresh errors', async () => {
    const revokeRefreshTokenFamily = vi.fn();

    const result = await handleRefreshTokenReuseDetection({
      error: { code: 'invalid_grant' },
      revokeRefreshTokenFamily,
    });

    expect(result).toEqual({
      handled: false,
      revoked: {
        refreshTokenFamily: false,
        session: false,
        deviceSession: false,
      },
    });
    expect(revokeRefreshTokenFamily).not.toHaveBeenCalled();
    expect(isRefreshTokenReuseDetected({ details: { originalError: 'refresh_token_reuse_detected' } })).toBe(true);
  });
});
