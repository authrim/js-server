import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IntrospectionClient } from '../../src/token/introspection.js';
import type { HttpProvider } from '../../src/providers/http.js';

describe('IntrospectionClient', () => {
  let mockHttp: HttpProvider;
  let client: IntrospectionClient;

  beforeEach(() => {
    mockHttp = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ active: true, sub: 'user123' }),
      }),
    };

    client = new IntrospectionClient({
      endpoint: 'https://auth.example.com/introspect',
      clientId: 'my-client',
      clientSecret: 'my-secret',
      http: mockHttp,
    });
  });

  describe('successful introspection', () => {
    it('should introspect an active token', async () => {
      const result = await client.introspect({ token: 'valid-token' });

      expect(result.active).toBe(true);
      expect(result.sub).toBe('user123');
    });

    it('should send correct request format', async () => {
      await client.introspect({ token: 'test-token' });

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/introspect',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
          }),
        })
      );

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = call[1].body as string;
      expect(body).toContain('token=test-token');
    });

    it('should include token_type_hint when provided', async () => {
      await client.introspect({
        token: 'test-token',
        token_type_hint: 'access_token',
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = call[1].body as string;
      expect(body).toContain('token_type_hint=access_token');
    });

    it('should use Basic auth with URL-encoded credentials', async () => {
      // Create client with special characters in credentials
      client = new IntrospectionClient({
        endpoint: 'https://auth.example.com/introspect',
        clientId: 'client:id',
        clientSecret: 'secret&value',
        http: mockHttp,
      });

      await client.introspect({ token: 'test-token' });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const authHeader = call[1].headers.Authorization;
      expect(authHeader).toMatch(/^Basic /);

      // Decode and verify URL encoding
      const credentials = Buffer.from(authHeader.replace('Basic ', ''), 'base64').toString();
      expect(credentials).toBe('client%3Aid:secret%26value');
    });
  });

  describe('inactive token', () => {
    it('should handle inactive token response', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ active: false }),
      });

      const result = await client.introspect({ token: 'expired-token' });

      expect(result.active).toBe(false);
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

      await expect(client.introspect({ token: 'test-token' }))
        .rejects.toThrow('Introspection request failed: 401 Unauthorized');
    });

    it('should throw on network error', async () => {
      mockHttp.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

      await expect(client.introspect({ token: 'test-token' }))
        .rejects.toThrow('Introspection request failed: Network failure');
    });

    it('should include original error message', async () => {
      mockHttp.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

      try {
        await client.introspect({ token: 'test-token' });
        expect.fail('Should have thrown');
      } catch (error) {
        expect((error as Error).message).toContain('Connection refused');
      }
    });
  });

  describe('response parsing', () => {
    it('should parse full introspection response', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          active: true,
          sub: 'user123',
          client_id: 'client-app',
          scope: 'read write',
          exp: 1700000000,
          iat: 1699996400,
          token_type: 'Bearer',
        }),
      });

      const result = await client.introspect({ token: 'test-token' });

      expect(result.active).toBe(true);
      expect(result.sub).toBe('user123');
      expect(result.client_id).toBe('client-app');
      expect(result.scope).toBe('read write');
      expect(result.exp).toBe(1700000000);
      expect(result.token_type).toBe('Bearer');
    });
  });
});
