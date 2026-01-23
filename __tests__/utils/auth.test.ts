import { describe, it, expect } from 'vitest';
import { encodeBasicCredentials } from '../../src/utils/auth.js';

describe('encodeBasicCredentials', () => {
  describe('basic encoding', () => {
    it('should encode simple credentials', () => {
      const result = encodeBasicCredentials('client_id', 'client_secret');
      // client_id:client_secret in base64
      expect(result).toBe(btoa('client_id:client_secret'));
    });

    it('should encode empty strings', () => {
      const result = encodeBasicCredentials('', '');
      expect(result).toBe(btoa(':'));
    });
  });

  describe('RFC 7617 URL encoding', () => {
    it('should URL-encode colons in client_id', () => {
      // Per RFC 7617, special characters should be percent-encoded
      const result = encodeBasicCredentials('client:id', 'secret');
      // client%3Aid:secret in base64
      expect(result).toBe(btoa('client%3Aid:secret'));
    });

    it('should URL-encode colons in client_secret', () => {
      const result = encodeBasicCredentials('client', 'sec:ret');
      expect(result).toBe(btoa('client:sec%3Aret'));
    });

    it('should URL-encode special characters', () => {
      const result = encodeBasicCredentials('client@id', 'secret&value');
      expect(result).toBe(btoa('client%40id:secret%26value'));
    });

    it('should URL-encode spaces', () => {
      const result = encodeBasicCredentials('client id', 'secret value');
      expect(result).toBe(btoa('client%20id:secret%20value'));
    });

    it('should URL-encode plus signs', () => {
      const result = encodeBasicCredentials('client+id', 'secret+value');
      expect(result).toBe(btoa('client%2Bid:secret%2Bvalue'));
    });

    it('should URL-encode percent signs', () => {
      const result = encodeBasicCredentials('client%id', 'secret%value');
      expect(result).toBe(btoa('client%25id:secret%25value'));
    });
  });

  describe('UTF-8 encoding', () => {
    it('should handle unicode characters', () => {
      const result = encodeBasicCredentials('クライアント', 'シークレット');
      // encodeURIComponent handles unicode
      const expected = btoa(encodeURIComponent('クライアント') + ':' + encodeURIComponent('シークレット'));
      expect(result).toBe(expected);
    });

    it('should handle emoji', () => {
      const result = encodeBasicCredentials('client🔑', 'secret🔐');
      const expected = btoa(encodeURIComponent('client🔑') + ':' + encodeURIComponent('secret🔐'));
      expect(result).toBe(expected);
    });
  });

  describe('edge cases', () => {
    it('should handle very long credentials', () => {
      const longId = 'a'.repeat(1000);
      const longSecret = 'b'.repeat(1000);
      const result = encodeBasicCredentials(longId, longSecret);

      // Decode and verify
      const decoded = atob(result);
      expect(decoded).toBe(`${longId}:${longSecret}`);
    });

    it('should handle credentials with only special characters', () => {
      const result = encodeBasicCredentials('!@#$%', '^&*()');
      const expected = btoa(encodeURIComponent('!@#$%') + ':' + encodeURIComponent('^&*()'));
      expect(result).toBe(expected);
    });
  });
});
