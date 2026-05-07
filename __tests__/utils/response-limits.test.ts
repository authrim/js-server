import { describe, expect, it } from 'vitest';
import {
  readResponseJsonWithLimit,
  readResponseTextPreview,
  readResponseTextWithLimit,
} from '../../src/utils/response-limits.js';

describe('response limit helpers', () => {
  it('rejects streamed responses that exceed the byte limit', async () => {
    const response = new Response('x'.repeat(12));

    await expect(readResponseTextWithLimit(response, 4)).rejects.toThrow(
      /exceeds maximum size/
    );
  });

  it('rejects responses with an oversized content-length before buffering', async () => {
    const response = new Response('small', {
      headers: { 'content-length': '100' },
    });

    await expect(readResponseTextWithLimit(response, 10)).rejects.toThrow(
      /exceeds maximum size/
    );
  });

  it('parses JSON within the byte limit', async () => {
    const response = new Response(JSON.stringify({ ok: true }));

    await expect(readResponseJsonWithLimit<{ ok: boolean }>(response, 64)).resolves.toEqual({
      ok: true,
    });
  });

  it('returns only a bounded preview for diagnostic bodies', async () => {
    const response = new Response('abcdef');

    await expect(readResponseTextPreview(response, 3)).resolves.toBe('abc');
  });
});
