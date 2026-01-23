import { describe, it, expect } from 'vitest';
import { timingSafeEqual, timingSafeEqualBytes } from '../../src/utils/timing-safe.js';

describe('timingSafeEqual', () => {
  describe('equal strings', () => {
    it('should return true for identical strings', () => {
      expect(timingSafeEqual('hello', 'hello')).toBe(true);
    });

    it('should return true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true);
    });

    it('should return true for single character strings', () => {
      expect(timingSafeEqual('a', 'a')).toBe(true);
    });

    it('should return true for long identical strings', () => {
      const longString = 'a'.repeat(10000);
      expect(timingSafeEqual(longString, longString)).toBe(true);
    });

    it('should return true for strings with special characters', () => {
      expect(timingSafeEqual('!@#$%^&*()', '!@#$%^&*()')).toBe(true);
    });

    it('should return true for strings with unicode characters', () => {
      expect(timingSafeEqual('こんにちは', 'こんにちは')).toBe(true);
      expect(timingSafeEqual('🔐🔑', '🔐🔑')).toBe(true);
    });
  });

  describe('different strings - same length', () => {
    it('should return false for different strings of same length', () => {
      expect(timingSafeEqual('hello', 'world')).toBe(false);
    });

    it('should return false when first character differs', () => {
      expect(timingSafeEqual('abc', 'xbc')).toBe(false);
    });

    it('should return false when middle character differs', () => {
      expect(timingSafeEqual('abc', 'axc')).toBe(false);
    });

    it('should return false when last character differs', () => {
      expect(timingSafeEqual('abc', 'abx')).toBe(false);
    });

    it('should return false for case-sensitive differences', () => {
      expect(timingSafeEqual('Hello', 'hello')).toBe(false);
      expect(timingSafeEqual('ABC', 'abc')).toBe(false);
    });
  });

  describe('different strings - different length', () => {
    it('should return false for different length strings', () => {
      expect(timingSafeEqual('hello', 'hello!')).toBe(false);
    });

    it('should return false when one is empty', () => {
      expect(timingSafeEqual('', 'hello')).toBe(false);
      expect(timingSafeEqual('hello', '')).toBe(false);
    });

    it('should return false for prefix/suffix relationships', () => {
      expect(timingSafeEqual('abc', 'abcd')).toBe(false);
      expect(timingSafeEqual('abcd', 'abc')).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle strings with null bytes', () => {
      expect(timingSafeEqual('a\0b', 'a\0b')).toBe(true);
      expect(timingSafeEqual('a\0b', 'a\0c')).toBe(false);
    });

    it('should handle strings with newlines', () => {
      expect(timingSafeEqual('a\nb', 'a\nb')).toBe(true);
      expect(timingSafeEqual('a\nb', 'a\nc')).toBe(false);
    });

    it('should handle strings with tabs', () => {
      expect(timingSafeEqual('a\tb', 'a\tb')).toBe(true);
      expect(timingSafeEqual('a\tb', 'a b')).toBe(false);
    });

    it('should handle multi-byte unicode correctly', () => {
      // These look similar but are different unicode characters
      expect(timingSafeEqual('é', 'é')).toBe(true); // Same character
      expect(timingSafeEqual('é', 'e\u0301')).toBe(false); // Different encoding
    });
  });

  describe('realistic scenarios', () => {
    it('should compare tokens correctly', () => {
      const token1 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const token2 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const token3 = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9';

      expect(timingSafeEqual(token1, token2)).toBe(true);
      expect(timingSafeEqual(token1, token3)).toBe(false);
    });

    it('should compare API keys correctly', () => {
      const key1 = 'sk_live_1234567890abcdef';
      const key2 = 'sk_live_1234567890abcdef';
      const key3 = 'sk_test_1234567890abcdef';

      expect(timingSafeEqual(key1, key2)).toBe(true);
      expect(timingSafeEqual(key1, key3)).toBe(false);
    });
  });
});

describe('timingSafeEqualBytes', () => {
  describe('equal arrays', () => {
    it('should return true for identical arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 5]);
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });

    it('should return true for empty arrays', () => {
      const a = new Uint8Array([]);
      const b = new Uint8Array([]);
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });

    it('should return true for single byte arrays', () => {
      const a = new Uint8Array([42]);
      const b = new Uint8Array([42]);
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });

    it('should return true for large identical arrays', () => {
      const a = new Uint8Array(10000).fill(0xAB);
      const b = new Uint8Array(10000).fill(0xAB);
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });

    it('should return true for arrays with all byte values', () => {
      const a = new Uint8Array(256);
      const b = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        a[i] = i;
        b[i] = i;
      }
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });
  });

  describe('different arrays - same length', () => {
    it('should return false for different arrays of same length', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
    });

    it('should return false when first byte differs', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([0, 2, 3]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
    });

    it('should return false when middle byte differs', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 0, 3]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
    });

    it('should return false when last byte differs', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 0]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
    });
  });

  describe('different arrays - different length', () => {
    it('should return false for different length arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
    });

    it('should return false when one is empty', () => {
      const a = new Uint8Array([]);
      const b = new Uint8Array([1, 2, 3]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
      expect(timingSafeEqualBytes(b, a)).toBe(false);
    });

    it('should return false for prefix relationships', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4, 5]);
      expect(timingSafeEqualBytes(a, b)).toBe(false);
      expect(timingSafeEqualBytes(b, a)).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle arrays with zero bytes', () => {
      const a = new Uint8Array([0, 0, 0]);
      const b = new Uint8Array([0, 0, 0]);
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });

    it('should handle arrays with max byte value', () => {
      const a = new Uint8Array([255, 255, 255]);
      const b = new Uint8Array([255, 255, 255]);
      expect(timingSafeEqualBytes(a, b)).toBe(true);
    });

    it('should detect single bit difference', () => {
      const a = new Uint8Array([0b10101010]);
      const b = new Uint8Array([0b10101011]); // Last bit different
      expect(timingSafeEqualBytes(a, b)).toBe(false);
    });
  });

  describe('realistic scenarios', () => {
    it('should compare hash digests correctly', () => {
      // Simulated SHA-256 digests
      const hash1 = new Uint8Array(32).fill(0xAB);
      const hash2 = new Uint8Array(32).fill(0xAB);
      const hash3 = new Uint8Array(32).fill(0xCD);

      expect(timingSafeEqualBytes(hash1, hash2)).toBe(true);
      expect(timingSafeEqualBytes(hash1, hash3)).toBe(false);
    });

    it('should compare signature bytes correctly', () => {
      const sig1 = new Uint8Array([0x30, 0x45, 0x02, 0x21, 0x00]);
      const sig2 = new Uint8Array([0x30, 0x45, 0x02, 0x21, 0x00]);
      const sig3 = new Uint8Array([0x30, 0x45, 0x02, 0x21, 0x01]);

      expect(timingSafeEqualBytes(sig1, sig2)).toBe(true);
      expect(timingSafeEqualBytes(sig1, sig3)).toBe(false);
    });
  });
});
