/**
 * HTTP Provider Interface
 *
 * Platform-agnostic HTTP client abstraction.
 * This interface uses the standard fetch API signature for maximum compatibility.
 */

/**
 * HTTP Provider interface
 *
 * Implementations should:
 * - Use the platform's native fetch or equivalent
 * - Handle timeout via AbortSignal
 * - Propagate network errors appropriately
 *
 * This interface follows the standard fetch API signature to ensure
 * compatibility across all runtime environments (Node.js, Bun, Deno,
 * Cloudflare Workers, Vercel Edge Functions).
 */
export interface HttpProvider {
  /**
   * Make an HTTP request
   *
   * @param input - URL or Request object
   * @param init - Request options
   * @returns Promise resolving to a Response
   * @throws Error on network failure or timeout
   */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}
