/**
 * In-Memory Cache Provider Implementation
 *
 * Simple TTL-based cache with optional size limits.
 */

import type { CacheProvider } from '../providers/cache.js';
import type { MemoryCacheOptions } from '../types/config.js';

/**
 * Cache entry with expiration
 */
interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

/**
 * Create an in-memory cache provider
 *
 * Features:
 * - TTL-based expiration
 * - Optional size limits with LRU eviction
 * - Lazy cleanup on access
 *
 * @param options - Cache configuration options
 * @returns CacheProvider implementation
 */
export function memoryCache<T>(options: MemoryCacheOptions = {}): CacheProvider<T> {
  const { ttlMs = 3600_000, maxSize = 1000 } = options;
  const cache = new Map<string, CacheEntry<T>>();

  /**
   * Remove expired entries and enforce size limit
   */
  function cleanup(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of cache.entries()) {
      if (entry.expiresAt <= now) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      cache.delete(key);
    }

    // Enforce max size (LRU: oldest entries first in Map iteration order)
    if (cache.size > maxSize) {
      const excess = cache.size - maxSize;
      const keysIterator = cache.keys();
      for (let i = 0; i < excess; i++) {
        const result = keysIterator.next();
        if (!result.done) {
          cache.delete(result.value);
        }
      }
    }
  }

  return {
    get(key: string): T | undefined {
      const entry = cache.get(key);
      if (!entry) {
        return undefined;
      }

      // Check expiration
      if (entry.expiresAt <= Date.now()) {
        cache.delete(key);
        return undefined;
      }

      // Move to end for LRU
      cache.delete(key);
      cache.set(key, entry);

      return entry.value;
    },

    set(key: string, value: T, entryTtlMs?: number): void {
      // If key already exists, just update it
      if (cache.has(key)) {
        cache.delete(key); // Remove to reset LRU position
      } else if (cache.size >= maxSize) {
        // Need to make room for new entry
        cleanup();
        // If still at max after cleanup, remove oldest
        if (cache.size >= maxSize) {
          const oldestKey = cache.keys().next().value;
          if (oldestKey !== undefined) {
            cache.delete(oldestKey);
          }
        }
      }

      const expiresAt = Date.now() + (entryTtlMs ?? ttlMs);
      cache.set(key, { value, expiresAt });
    },

    delete(key: string): void {
      cache.delete(key);
    },

    clear(): void {
      cache.clear();
    },
  };
}
