import { describe, it, expect, vi, beforeEach } from 'vitest';
import { authenticateRequest } from '../../src/middleware/authenticate.js';
import type { AuthrimServer } from '../../src/core/client.js';
import type { AuthenticateRequest } from '../../src/middleware/types.js';

// Mock AuthrimServer
function createMockServer(overrides: {
  validateToken?: ReturnType<typeof vi.fn>;
  validateDPoP?: ReturnType<typeof vi.fn>;
} = {}): AuthrimServer {
  return {
    validateToken: overrides.validateToken ?? vi.fn(),
    validateDPoP: overrides.validateDPoP ?? vi.fn(),
    init: vi.fn(),
    getConfig: vi.fn(),
    invalidateJwksCache: vi.fn(),
    introspect: vi.fn(),
    revoke: vi.fn(),
  } as unknown as AuthrimServer;
}

describe('authenticateRequest', () => {
  describe('Authorization header parsing', () => {
    it('should return error for missing Authorization header', async () => {
      const server = createMockServer();
      const request: AuthenticateRequest = {
        headers: {},
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.error?.code).toBe('invalid_token');
      expect(result.error?.message).toContain('Missing or invalid Authorization header');
    });

    it('should return error for invalid Authorization format', async () => {
      const server = createMockServer();
      const request: AuthenticateRequest = {
        headers: { authorization: 'InvalidFormat' },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.error?.code).toBe('invalid_token');
    });

    it('should return error for unsupported scheme', async () => {
      const server = createMockServer();
      const request: AuthenticateRequest = {
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.error?.code).toBe('invalid_token');
    });

    it('should parse Bearer token', async () => {
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims: { sub: 'user123' },
          token: 'test-token',
          tokenType: 'Bearer',
        },
        error: null,
      });
      const server = createMockServer({ validateToken });
      const request: AuthenticateRequest = {
        headers: { authorization: 'Bearer test-token' },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      await authenticateRequest(server, request);

      expect(validateToken).toHaveBeenCalledWith('test-token');
    });

    it('should be case-insensitive for header names', async () => {
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims: { sub: 'user123' },
          token: 'test-token',
          tokenType: 'Bearer',
        },
        error: null,
      });
      const server = createMockServer({ validateToken });
      const request: AuthenticateRequest = {
        headers: { 'AUTHORIZATION': 'Bearer test-token' },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      await authenticateRequest(server, request);

      expect(validateToken).toHaveBeenCalled();
    });
  });

  describe('Token validation', () => {
    it('should return validated claims on success', async () => {
      const claims = {
        sub: 'user123',
        iss: 'https://issuer.example.com',
        aud: 'https://api.example.com',
      };
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims,
          token: 'test-token',
          tokenType: 'Bearer',
        },
        error: null,
      });
      const server = createMockServer({ validateToken });
      const request: AuthenticateRequest = {
        headers: { authorization: 'Bearer test-token' },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.data?.claims.claims).toEqual(claims);
      expect(result.data?.tokenType).toBe('Bearer');
      expect(result.error).toBeNull();
    });

    it('should return error when token validation fails', async () => {
      const validateToken = vi.fn().mockResolvedValue({
        data: null,
        error: { code: 'token_expired', message: 'Token has expired' },
      });
      const server = createMockServer({ validateToken });
      const request: AuthenticateRequest = {
        headers: { authorization: 'Bearer expired-token' },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.data).toBeNull();
      expect(result.error?.code).toBe('token_expired');
    });
  });

  describe('DPoP validation', () => {
    it('should validate DPoP proof when using DPoP scheme', async () => {
      const claims = {
        sub: 'user123',
        cnf: { jkt: 'thumbprint123' },
      };
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims,
          token: 'test-token',
          tokenType: 'DPoP',
        },
        error: null,
      });
      const validateDPoP = vi.fn().mockResolvedValue({
        valid: true,
        thumbprint: 'thumbprint123',
      });
      const server = createMockServer({ validateToken, validateDPoP });
      const request: AuthenticateRequest = {
        headers: {
          authorization: 'DPoP test-token',
          dpop: 'dpop-proof-jwt',
        },
        method: 'POST',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(validateDPoP).toHaveBeenCalledWith('dpop-proof-jwt', {
        method: 'POST',
        uri: 'https://api.example.com/resource',
        accessToken: 'test-token',
        expectedThumbprint: 'thumbprint123',
      });
      expect(result.data?.tokenType).toBe('DPoP');
    });

    it('should validate DPoP proof when token has cnf claim', async () => {
      const claims = {
        sub: 'user123',
        cnf: { jkt: 'thumbprint123' },
      };
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims,
          token: 'test-token',
          tokenType: 'DPoP',
        },
        error: null,
      });
      const validateDPoP = vi.fn().mockResolvedValue({
        valid: true,
        thumbprint: 'thumbprint123',
      });
      const server = createMockServer({ validateToken, validateDPoP });
      const request: AuthenticateRequest = {
        headers: {
          authorization: 'Bearer test-token', // Bearer scheme but token has cnf
          dpop: 'dpop-proof-jwt',
        },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(validateDPoP).toHaveBeenCalled();
      expect(result.data?.tokenType).toBe('DPoP');
    });

    it('should return error when DPoP proof is missing', async () => {
      const claims = {
        sub: 'user123',
        cnf: { jkt: 'thumbprint123' },
      };
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims,
          token: 'test-token',
          tokenType: 'DPoP',
        },
        error: null,
      });
      const server = createMockServer({ validateToken });
      const request: AuthenticateRequest = {
        headers: {
          authorization: 'DPoP test-token',
          // Missing dpop header
        },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.error?.code).toBe('dpop_proof_missing');
    });

    it('should return error when DPoP validation fails', async () => {
      const claims = {
        sub: 'user123',
        cnf: { jkt: 'thumbprint123' },
      };
      const validateToken = vi.fn().mockResolvedValue({
        data: {
          claims,
          token: 'test-token',
          tokenType: 'DPoP',
        },
        error: null,
      });
      const validateDPoP = vi.fn().mockResolvedValue({
        valid: false,
        errorCode: 'dpop_binding_mismatch',
        errorMessage: 'Key binding mismatch',
      });
      const server = createMockServer({ validateToken, validateDPoP });
      const request: AuthenticateRequest = {
        headers: {
          authorization: 'DPoP test-token',
          dpop: 'invalid-dpop-proof',
        },
        method: 'GET',
        url: 'https://api.example.com/resource',
      };

      const result = await authenticateRequest(server, request);

      expect(result.error?.code).toBe('dpop_binding_mismatch');
    });
  });
});
