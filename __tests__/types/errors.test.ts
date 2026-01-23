import { describe, it, expect } from 'vitest';
import {
  AuthrimServerError,
  getServerErrorMeta,
} from '../../src/types/errors.js';

describe('AuthrimServerError', () => {
  it('should create error with code and message', () => {
    const error = new AuthrimServerError('invalid_token', 'Token is invalid');

    expect(error.code).toBe('invalid_token');
    expect(error.message).toBe('Token is invalid');
    expect(error.name).toBe('AuthrimServerError');
  });

  it('should include details', () => {
    const error = new AuthrimServerError('invalid_token', 'Token is invalid', {
      details: { hint: 'Check expiration' },
    });

    expect(error.details).toEqual({ hint: 'Check expiration' });
  });

  it('should include cause', () => {
    const cause = new Error('Original error');
    const error = new AuthrimServerError('network_error', 'Request failed', {
      cause,
    });

    expect(error.cause).toBe(cause);
  });

  it('should provide metadata via getter', () => {
    const error = new AuthrimServerError('token_expired', 'Token has expired');

    expect(error.meta.httpStatus).toBe(401);
    expect(error.meta.transient).toBe(false);
    expect(error.meta.retryable).toBe(false);
  });
});

describe('getServerErrorMeta', () => {
  describe('JWT validation errors', () => {
    it('should return 401 for invalid_token', () => {
      const meta = getServerErrorMeta('invalid_token');
      expect(meta.httpStatus).toBe(401);
      expect(meta.wwwAuthenticateError).toBe('invalid_token');
    });

    it('should return 401 for token_expired', () => {
      const meta = getServerErrorMeta('token_expired');
      expect(meta.httpStatus).toBe(401);
    });

    it('should return 401 for signature_invalid', () => {
      const meta = getServerErrorMeta('signature_invalid');
      expect(meta.httpStatus).toBe(401);
    });
  });

  describe('JWKS errors', () => {
    it('should return 503 for jwks_fetch_error', () => {
      const meta = getServerErrorMeta('jwks_fetch_error');
      expect(meta.httpStatus).toBe(503);
      expect(meta.transient).toBe(true);
      expect(meta.retryable).toBe(true);
    });

    it('should return 401 for jwks_key_not_found', () => {
      const meta = getServerErrorMeta('jwks_key_not_found');
      expect(meta.httpStatus).toBe(401);
      expect(meta.transient).toBe(true); // May be resolved by JWKS refresh
    });

    it('should return 500 for jwks_key_import_error', () => {
      const meta = getServerErrorMeta('jwks_key_import_error');
      expect(meta.httpStatus).toBe(500);
    });
  });

  describe('DPoP errors', () => {
    it('should return 401 for dpop_proof_missing', () => {
      const meta = getServerErrorMeta('dpop_proof_missing');
      expect(meta.httpStatus).toBe(401);
    });

    it('should return 401 for dpop_nonce_required with use_dpop_nonce', () => {
      const meta = getServerErrorMeta('dpop_nonce_required');
      expect(meta.httpStatus).toBe(401);
      expect(meta.wwwAuthenticateError).toBe('use_dpop_nonce');
      expect(meta.retryable).toBe(true);
    });
  });

  describe('Network errors', () => {
    it('should return 503 for network_error', () => {
      const meta = getServerErrorMeta('network_error');
      expect(meta.httpStatus).toBe(503);
      expect(meta.transient).toBe(true);
      expect(meta.retryable).toBe(true);
    });

    it('should return 504 for timeout_error', () => {
      const meta = getServerErrorMeta('timeout_error');
      expect(meta.httpStatus).toBe(504);
    });
  });

  describe('Configuration errors', () => {
    it('should return 500 for configuration_error', () => {
      const meta = getServerErrorMeta('configuration_error');
      expect(meta.httpStatus).toBe(500);
      expect(meta.retryable).toBe(false);
    });
  });
});
