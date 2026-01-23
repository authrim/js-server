/**
 * Fetch-based HTTP Provider Implementation
 *
 * Uses globalThis.fetch for maximum runtime compatibility.
 */

import type { HttpProvider } from '../providers/http.js';

/**
 * Create a fetch-based HTTP provider
 *
 * This implementation uses the global fetch API which is available in:
 * - Node.js 18+
 * - Bun
 * - Deno
 * - Cloudflare Workers
 * - Vercel Edge Functions
 * - All modern browsers
 *
 * @returns HttpProvider implementation
 */
export function fetchHttpProvider(): HttpProvider {
  return {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return globalThis.fetch(input, init);
    },
  };
}
