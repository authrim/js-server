import { describe, it, expect } from 'vitest';
import { buildErrorResponse, buildWwwAuthenticateHeader, buildErrorHeaders } from '../../src/utils/error-response.js';
import { AuthrimServerError } from '../../src/types/errors.js';

describe('buildErrorResponse', () => {
  it('should build error response from AuthrimServerError', () => {
    const error = new AuthrimServerError('invalid_token', 'Token has expired');

    const response = buildErrorResponse(error);

    expect(response).toEqual({
      error: 'invalid_token',
      error_description: 'Token has expired',
    });
  });

  it('should use server_error when no wwwAuthenticateError meta', () => {
    // configuration_error has no wwwAuthenticateError defined
    const error = new AuthrimServerError('configuration_error', 'Something went wrong');

    const response = buildErrorResponse(error);

    // When wwwAuthenticateError is undefined, it falls back to 'server_error'
    expect(response.error).toBe('server_error');
  });
});

describe('buildWwwAuthenticateHeader', () => {
  describe('basic functionality', () => {
    it('should build Bearer header with error', () => {
      const error = new AuthrimServerError('invalid_token', 'Token expired');

      const header = buildWwwAuthenticateHeader(error);

      expect(header).toBe('Bearer, error="invalid_token", error_description="Token expired"');
    });

    it('should include realm when provided', () => {
      const error = new AuthrimServerError('invalid_token', 'Token expired');

      const header = buildWwwAuthenticateHeader(error, 'example.com');

      expect(header).toBe('Bearer, realm="example.com", error="invalid_token", error_description="Token expired"');
    });

    it('should support DPoP scheme', () => {
      const error = new AuthrimServerError('invalid_token', 'Token expired');

      const header = buildWwwAuthenticateHeader(error, undefined, 'DPoP');

      expect(header).toBe('DPoP, error="invalid_token", error_description="Token expired"');
    });
  });

  describe('header injection prevention', () => {
    it('should remove newlines from realm (prevents header injection)', () => {
      const error = new AuthrimServerError('invalid_token', 'Error');
      const maliciousRealm = 'example.com\r\nX-Injected: malicious';

      const header = buildWwwAuthenticateHeader(error, maliciousRealm);

      // CR and LF are removed, preventing actual header injection
      expect(header).not.toContain('\r');
      expect(header).not.toContain('\n');
      // The text "X-Injected" remains but is safely inside quotes
      // so it cannot be interpreted as a new header
      expect(header).toContain('realm="example.comX-Injected: malicious"');
    });

    it('should remove carriage returns from error message (prevents header injection)', () => {
      const error = new AuthrimServerError('invalid_token', 'Error\r\nX-Injected: evil');

      const header = buildWwwAuthenticateHeader(error);

      // CR and LF are removed, preventing actual header injection
      expect(header).not.toContain('\r');
      expect(header).not.toContain('\n');
      // The malicious text is safely contained in quotes
      expect(header).toContain('error_description="ErrorX-Injected: evil"');
    });

    it('should escape double quotes', () => {
      const error = new AuthrimServerError('invalid_token', 'Token "expired"');

      const header = buildWwwAuthenticateHeader(error);

      // Double quotes should be escaped with backslash
      expect(header).toContain('\\"expired\\"');
    });

    it('should escape backslashes', () => {
      const error = new AuthrimServerError('invalid_token', 'Path C:\\Users\\test');

      const header = buildWwwAuthenticateHeader(error);

      expect(header).toContain('C:\\\\Users\\\\test');
    });

    it('should remove NULL bytes', () => {
      const error = new AuthrimServerError('invalid_token', 'Error\x00injected');

      const header = buildWwwAuthenticateHeader(error);

      expect(header).not.toContain('\x00');
    });

    it('should remove all control characters except tab', () => {
      const error = new AuthrimServerError(
        'invalid_token',
        'Error\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F'
      );

      const header = buildWwwAuthenticateHeader(error);

      // Should not contain any control characters
      expect(header).toMatch(/^[\x09\x20-\x7E]*$/);
    });

    it('should preserve tabs', () => {
      const error = new AuthrimServerError('invalid_token', 'Error\twith\ttabs');

      const header = buildWwwAuthenticateHeader(error);

      expect(header).toContain('\t');
    });

    it('should truncate very long values', () => {
      const longMessage = 'A'.repeat(1000);
      const error = new AuthrimServerError('invalid_token', longMessage);

      const header = buildWwwAuthenticateHeader(error);

      // The sanitized value should be at most 256 characters
      const descriptionMatch = header.match(/error_description="([^"]*)"/);
      expect(descriptionMatch).not.toBeNull();
      expect(descriptionMatch![1].length).toBeLessThanOrEqual(256);
    });

    it('should handle combined attack vectors (prevents actual header injection)', () => {
      const malicious = 'Error"\r\nSet-Cookie: session=evil\r\n\x00';
      const error = new AuthrimServerError('invalid_token', malicious);

      const header = buildWwwAuthenticateHeader(error);

      // CR, LF, and NULL bytes are removed - this prevents actual header injection
      expect(header).not.toContain('\r');
      expect(header).not.toContain('\n');
      expect(header).not.toContain('\x00');
      // Double quote should be escaped
      expect(header).toContain('\\"');
      // The text content is safely contained in quotes (no newlines means no header break)
      // "Set-Cookie" text remains but cannot be interpreted as header because:
      // 1. No newlines to create new header line
      // 2. Text is inside quotes as error_description value
      expect(header).toContain('error_description=');
    });
  });
});

describe('buildErrorHeaders', () => {
  it('should include Content-Type', () => {
    const error = new AuthrimServerError('invalid_token', 'Error');

    const headers = buildErrorHeaders(error);

    expect(headers['Content-Type']).toBe('application/json');
  });

  it('should include WWW-Authenticate for 401 errors', () => {
    const error = new AuthrimServerError('invalid_token', 'Error');

    const headers = buildErrorHeaders(error);

    expect(headers['WWW-Authenticate']).toBeDefined();
    expect(headers['WWW-Authenticate']).toContain('Bearer');
  });

  it('should not include WWW-Authenticate for non-401 errors', () => {
    // configuration_error has httpStatus 500, not 401
    const error = new AuthrimServerError('configuration_error', 'Configuration error');

    const headers = buildErrorHeaders(error);

    // 500 errors should not have WWW-Authenticate
    expect(error.meta.httpStatus).toBe(500);
    expect(headers['WWW-Authenticate']).toBeUndefined();
  });

  it('should include DPoP-Nonce for dpop_nonce_required errors', () => {
    const error = new AuthrimServerError('dpop_nonce_required', 'Nonce required');

    const headers = buildErrorHeaders(error, { dpopNonce: 'server-nonce-123' });

    expect(headers['DPoP-Nonce']).toBe('server-nonce-123');
  });

  it('should not include DPoP-Nonce without dpopNonce option', () => {
    const error = new AuthrimServerError('dpop_nonce_required', 'Nonce required');

    const headers = buildErrorHeaders(error);

    expect(headers['DPoP-Nonce']).toBeUndefined();
  });

  it('should use specified scheme', () => {
    const error = new AuthrimServerError('invalid_token', 'Error');

    const headers = buildErrorHeaders(error, { scheme: 'DPoP' });

    expect(headers['WWW-Authenticate']).toContain('DPoP');
    expect(headers['WWW-Authenticate']).not.toContain('Bearer');
  });
});
