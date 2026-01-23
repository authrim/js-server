import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { memoryCache } from '../../src/providers-impl/memory-cache.js';

describe('memoryCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('basic operations', () => {
    it('should store and retrieve values', () => {
      const cache = memoryCache<string>();

      cache.set('key1', 'value1');

      expect(cache.get('key1')).toBe('value1');
    });

    it('should return undefined for missing keys', () => {
      const cache = memoryCache<string>();

      expect(cache.get('nonexistent')).toBeUndefined();
    });

    it('should delete values', () => {
      const cache = memoryCache<string>();

      cache.set('key1', 'value1');
      cache.delete('key1');

      expect(cache.get('key1')).toBeUndefined();
    });

    it('should clear all values', () => {
      const cache = memoryCache<string>();

      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.clear?.();

      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBeUndefined();
    });
  });

  describe('TTL expiration', () => {
    it('should expire entries after default TTL', () => {
      const cache = memoryCache<string>({ ttlMs: 1000 });

      cache.set('key1', 'value1');

      // Before expiration
      expect(cache.get('key1')).toBe('value1');

      // After expiration
      vi.advanceTimersByTime(1001);
      expect(cache.get('key1')).toBeUndefined();
    });

    it('should use custom TTL per entry', () => {
      const cache = memoryCache<string>({ ttlMs: 10000 });

      cache.set('key1', 'value1', 500); // 500ms TTL

      expect(cache.get('key1')).toBe('value1');

      vi.advanceTimersByTime(501);
      expect(cache.get('key1')).toBeUndefined();
    });

    it('should not expire entries before TTL', () => {
      const cache = memoryCache<string>({ ttlMs: 1000 });

      cache.set('key1', 'value1');

      vi.advanceTimersByTime(999);
      expect(cache.get('key1')).toBe('value1');
    });
  });

  describe('max size limit', () => {
    it('should enforce max size limit', () => {
      const cache = memoryCache<string>({ maxSize: 3 });

      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');
      cache.set('key4', 'value4'); // Should trigger cleanup

      // At least one old entry should be evicted
      const values = [
        cache.get('key1'),
        cache.get('key2'),
        cache.get('key3'),
        cache.get('key4'),
      ];
      const definedValues = values.filter((v) => v !== undefined);

      expect(definedValues.length).toBeLessThanOrEqual(3);
      expect(cache.get('key4')).toBe('value4'); // Most recent should exist
    });
  });

  describe('LRU behavior', () => {
    it('should update access time on get', () => {
      const cache = memoryCache<string>({ maxSize: 2 });

      cache.set('key1', 'value1');
      cache.set('key2', 'value2');

      // Access key1 to make it more recent
      cache.get('key1');

      // Add key3, should evict key2 (least recently used)
      cache.set('key3', 'value3');

      expect(cache.get('key1')).toBe('value1');
      expect(cache.get('key3')).toBe('value3');
    });
  });

  describe('complex values', () => {
    it('should store objects', () => {
      const cache = memoryCache<{ id: number; name: string }>();

      const obj = { id: 1, name: 'test' };
      cache.set('key1', obj);

      expect(cache.get('key1')).toEqual(obj);
    });

    it('should store arrays', () => {
      const cache = memoryCache<number[]>();

      const arr = [1, 2, 3];
      cache.set('key1', arr);

      expect(cache.get('key1')).toEqual(arr);
    });
  });
});
