/**
 * Cache Provider Interface
 *
 * Generic caching abstraction for JWKS and other cacheable data.
 */

/**
 * Cache Provider interface
 *
 * Implementations should:
 * - Support TTL-based expiration
 * - Be thread-safe in concurrent environments
 * - Handle memory limits gracefully
 *
 * @template T - Type of cached values
 */
export interface CacheProvider<T> {
  /**
   * Get a cached value
   *
   * @param key - Cache key
   * @returns Cached value or undefined if not found/expired
   */
  get(key: string): T | undefined;

  /**
   * Set a cached value
   *
   * @param key - Cache key
   * @param value - Value to cache
   * @param ttlMs - Time-to-live in milliseconds (optional, uses default if not provided)
   */
  set(key: string, value: T, ttlMs?: number): void;

  /**
   * Delete a cached value
   *
   * @param key - Cache key
   */
  delete(key: string): void;

  /**
   * Clear all cached values (optional)
   *
   * May be a no-op in some implementations (e.g., distributed caches).
   */
  clear?(): void;
}
