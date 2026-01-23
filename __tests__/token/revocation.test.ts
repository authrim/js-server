import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RevocationClient } from '../../src/token/revocation.js';
import type { HttpProvider } from '../../src/providers/http.js';

describe('RevocationClient', () => {
  let mockHttp: HttpProvider;
  let client: RevocationClient;

  beforeEach(() => {
    mockHttp = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
      }),
    };

    client = new RevocationClient({
      endpoint: 'https://auth.example.com/revoke',
      clientId: 'my-client',
      clientSecret: 'my-secret',
      http: mockHttp,
    });
  });

  describe('successful revocation', () => {
    it('should revoke a token successfully', async () => {
      await expect(client.revoke({ token: 'valid-token' })).resolves.toBeUndefined();
    });

    it('should send correct request format', async () => {
      await client.revoke({ token: 'test-token' });

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/revoke',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
          }),
        })
      );

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = call[1].body as string;
      expect(body).toContain('token=test-token');
    });

    it('should include token_type_hint when provided', async () => {
      await client.revoke({
        token: 'test-token',
        token_type_hint: 'refresh_token',
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = call[1].body as string;
      expect(body).toContain('token_type_hint=refresh_token');
    });

    it('should use Basic auth with URL-encoded credentials', async () => {
      // Create client with special characters in credentials
      client = new RevocationClient({
        endpoint: 'https://auth.example.com/revoke',
        clientId: 'client:id',
        clientSecret: 'secret&value',
        http: mockHttp,
      });

      await client.revoke({ token: 'test-token' });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const authHeader = call[1].headers.Authorization;
      expect(authHeader).toMatch(/^Basic /);

      // Decode and verify URL encoding
      const credentials = Buffer.from(authHeader.replace('Basic ', ''), 'base64').toString();
      expect(credentials).toBe('client%3Aid:secret%26value');
    });
  });

  describe('RFC 7009 compliance', () => {
    it('should succeed even if token is already revoked (200 response)', async () => {
      // Per RFC 7009, server returns 200 even for already-revoked tokens
      mockHttp.fetch = vi.fn().mockResolvedValue({ ok: true });

      await expect(client.revoke({ token: 'already-revoked' })).resolves.toBeUndefined();
    });

    it('should succeed even if token is invalid (200 response)', async () => {
      // Per RFC 7009, server returns 200 even for invalid tokens
      mockHttp.fetch = vi.fn().mockResolvedValue({ ok: true });

      await expect(client.revoke({ token: 'invalid-token' })).resolves.toBeUndefined();
    });
  });

  describe('error handling', () => {
    it('should throw on HTTP error', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: vi.fn().mockResolvedValue(''),
      });

      await expect(client.revoke({ token: 'test-token' }))
        .rejects.toThrow('Revocation request failed: 401 Unauthorized');
    });

    it('should throw on network error', async () => {
      mockHttp.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

      await expect(client.revoke({ token: 'test-token' }))
        .rejects.toThrow('Revocation request failed: Network failure');
    });

    it('should include original error message', async () => {
      mockHttp.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

      try {
        await client.revoke({ token: 'test-token' });
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toContain('Connection refused');
      }
    });

    it('should throw on 400 Bad Request', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: vi.fn().mockResolvedValue(''),
      });

      await expect(client.revoke({ token: 'test-token' }))
        .rejects.toThrow('400 Bad Request');
    });
  });

  describe('token type hints', () => {
    it('should support access_token hint', async () => {
      await client.revoke({
        token: 'test-access-token',
        token_type_hint: 'access_token',
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = call[1].body as string;
      expect(body).toContain('token_type_hint=access_token');
    });

    it('should support refresh_token hint', async () => {
      await client.revoke({
        token: 'test-refresh-token',
        token_type_hint: 'refresh_token',
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = call[1].body as string;
      expect(body).toContain('token_type_hint=refresh_token');
    });
  });
});
