import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchHttpProvider } from '../../src/providers-impl/fetch-http.js';

describe('fetchHttpProvider', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('applies a default timeout signal to fetch requests', async () => {
    vi.useFakeTimers();
    let capturedSignal: AbortSignal | undefined;

    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        capturedSignal = init?.signal;
        return new Promise<Response>((_resolve, reject) => {
          capturedSignal?.addEventListener('abort', () => {
            const error = new Error('aborted');
            error.name = 'AbortError';
            reject(error);
          });
        });
      })
    );

    const provider = fetchHttpProvider({ timeout: 10 });
    const promise = provider.fetch('https://auth.example.com/.well-known/jwks.json');
    const assertion = expect(promise).rejects.toThrow('aborted');

    await vi.advanceTimersByTimeAsync(10);

    await assertion;
    expect(capturedSignal?.aborted).toBe(true);
  });

  it('propagates caller cancellation into the composed fetch signal', async () => {
    let capturedSignal: AbortSignal | undefined;

    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        capturedSignal = init?.signal;
        return new Promise<Response>((_resolve, reject) => {
          capturedSignal?.addEventListener('abort', () => {
            const error = new Error('aborted');
            error.name = 'AbortError';
            reject(error);
          });
        });
      })
    );

    const callerController = new AbortController();
    const provider = fetchHttpProvider({ timeout: 30000 });
    const promise = provider.fetch('https://auth.example.com/.well-known/jwks.json', {
      signal: callerController.signal,
    });
    const assertion = expect(promise).rejects.toThrow('aborted');

    callerController.abort();

    await assertion;
    expect(capturedSignal?.aborted).toBe(true);
  });

  it('allows provider-level timeout to be disabled', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    const provider = fetchHttpProvider({ timeout: 0 });
    const response = await provider.fetch('https://auth.example.com/.well-known/jwks.json');

    expect(response.status).toBe(204);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://auth.example.com/.well-known/jwks.json',
      undefined
    );
  });
});
