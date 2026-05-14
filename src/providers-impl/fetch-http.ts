/**
 * Fetch-based HTTP Provider Implementation
 *
 * Uses globalThis.fetch for maximum runtime compatibility.
 */

import type { HttpProvider } from '../providers/http.js';

/**
 * Fetch provider options.
 */
export interface FetchHttpProviderOptions {
  /**
   * Default request timeout in milliseconds.
   *
   * Set to 0 or a negative value to disable the provider-level timeout.
   */
  timeout?: number;
}

const DEFAULT_FETCH_TIMEOUT_MS = 30000;

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
export function fetchHttpProvider(options: FetchHttpProviderOptions = {}): HttpProvider {
  const defaultTimeout = options.timeout ?? DEFAULT_FETCH_TIMEOUT_MS;

  return {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      return fetchWithTimeout(input, init, defaultTimeout);
    },
  };
}

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  timeoutMs: number
): Promise<Response> {
  if (timeoutMs <= 0) {
    return globalThis.fetch(input, init);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  const upstreamSignal = init?.signal;

  const abortFromUpstream = () => controller.abort();
  if (upstreamSignal?.aborted) {
    controller.abort();
  } else {
    upstreamSignal?.addEventListener('abort', abortFromUpstream, { once: true });
  }

  try {
    return await globalThis.fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
    upstreamSignal?.removeEventListener('abort', abortFromUpstream);
  }
}
