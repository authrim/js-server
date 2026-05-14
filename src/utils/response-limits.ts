const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

export async function readResponseTextWithLimit(
  response: Response,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES
): Promise<string> {
  if (maxBytes <= 0) {
    return response.text();
  }

  const contentLength = response.headers?.get?.('content-length');
  if (contentLength) {
    const parsed = Number.parseInt(contentLength, 10);
    if (Number.isFinite(parsed) && parsed > maxBytes) {
      throw new Error(`Response body exceeds maximum size: ${parsed} > ${maxBytes} bytes`);
    }
  }

  if (!response.body) {
    const text =
      typeof response.text === 'function'
        ? await response.text()
        : typeof response.json === 'function'
          ? JSON.stringify(await response.json())
          : '';
    const byteLength = new TextEncoder().encode(text).byteLength;
    if (byteLength > maxBytes) {
      throw new Error(`Response body exceeds maximum size: ${byteLength} > ${maxBytes} bytes`);
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        void reader.cancel().catch(() => {});
        throw new Error(`Response body exceeds maximum size: ${totalBytes} > ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder().decode(body);
}

export async function readResponseTextPreview(
  response: Response,
  maxBytes: number
): Promise<string> {
  if (maxBytes <= 0) {
    return '';
  }

  if (!response.body) {
    const text =
      typeof response.text === 'function'
        ? await response.text().catch(() => '')
        : typeof response.json === 'function'
          ? JSON.stringify(await response.json().catch(() => null) ?? '')
          : '';
    return text.length > maxBytes ? text.slice(0, maxBytes) : text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let truncated = false;

  try {
    while (totalBytes < maxBytes) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }

      const remaining = maxBytes - totalBytes;
      if (value.byteLength > remaining) {
        chunks.push(value.slice(0, remaining));
        totalBytes += remaining;
        truncated = true;
        break;
      }

      chunks.push(value);
      totalBytes += value.byteLength;
    }

    if (totalBytes >= maxBytes) {
      truncated = true;
    }
    if (truncated) {
      void reader.cancel().catch(() => {});
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder().decode(body);
}

export async function readResponseJsonWithLimit<T>(
  response: Response,
  maxBytes = DEFAULT_MAX_RESPONSE_BYTES
): Promise<T> {
  const text = await readResponseTextWithLimit(response, maxBytes);
  return JSON.parse(text) as T;
}
