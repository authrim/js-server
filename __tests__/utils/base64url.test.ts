import { describe, it, expect } from 'vitest';
import {
  base64UrlEncode,
  base64UrlDecode,
  base64UrlEncodeString,
  base64UrlDecodeString,
} from '../../src/utils/base64url.js';

describe('base64url', () => {
  describe('base64UrlEncode', () => {
    it('should encode empty array', () => {
      const result = base64UrlEncode(new Uint8Array([]));
      expect(result).toBe('');
    });

    it('should encode bytes without padding', () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const result = base64UrlEncode(bytes);
      expect(result).toBe('SGVsbG8');
      expect(result).not.toContain('='); // No padding
    });

    it('should use URL-safe characters', () => {
      // Bytes that would produce + and / in standard base64
      const bytes = new Uint8Array([251, 239, 190]); // produces ++++
      const result = base64UrlEncode(bytes);
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
      expect(result).toContain('-'); // URL-safe replacement for +
    });
  });

  describe('base64UrlDecode', () => {
    it('should decode empty string', () => {
      const result = base64UrlDecode('');
      expect(result).toEqual(new Uint8Array([]));
    });

    it('should decode without padding', () => {
      const result = base64UrlDecode('SGVsbG8');
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should decode with URL-safe characters', () => {
      const encoded = base64UrlEncode(new Uint8Array([251, 239, 190]));
      const decoded = base64UrlDecode(encoded);
      expect(decoded).toEqual(new Uint8Array([251, 239, 190]));
    });

    it('should handle standard base64 input with padding', () => {
      const result = base64UrlDecode('SGVsbG8=');
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });
  });

  describe('base64UrlEncodeString / base64UrlDecodeString', () => {
    it('should round-trip ASCII string', () => {
      const original = 'Hello, World!';
      const encoded = base64UrlEncodeString(original);
      const decoded = base64UrlDecodeString(encoded);
      expect(decoded).toBe(original);
    });

    it('should round-trip Unicode string', () => {
      const original = 'こんにちは世界';
      const encoded = base64UrlEncodeString(original);
      const decoded = base64UrlDecodeString(encoded);
      expect(decoded).toBe(original);
    });

    it('should round-trip emoji string', () => {
      const original = '🔐🔑🔒';
      const encoded = base64UrlEncodeString(original);
      const decoded = base64UrlDecodeString(encoded);
      expect(decoded).toBe(original);
    });
  });

  describe('JWT compatibility', () => {
    it('should decode JWT header', () => {
      // {"alg":"RS256","typ":"JWT"}
      const header = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9';
      const decoded = base64UrlDecodeString(header);
      const parsed = JSON.parse(decoded);
      expect(parsed).toEqual({ alg: 'RS256', typ: 'JWT' });
    });

    it('should encode JWT-like payload', () => {
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      const encoded = base64UrlEncodeString(JSON.stringify(payload));
      const decoded = base64UrlDecodeString(encoded);
      expect(JSON.parse(decoded)).toEqual(payload);
    });
  });
});
