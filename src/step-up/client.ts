import type { HttpProvider } from '../providers/http.js';
import {
  AuthrimServerError,
  createServerErrorFromOAuthResponse,
  type AuthrimOAuthErrorResponse,
  type AuthrimServerErrorCode,
} from '../types/errors.js';
import type {
  StepUpActionResponse,
  StepUpCompleteRequest,
  StepUpStartRequest,
} from '../types/step-up.js';

export interface StepUpClientConfig {
  /** Canonical Step-Up endpoint base, usually `{issuer}/auth/step-up`. */
  endpoint: string;
  /** HTTP provider. */
  http: HttpProvider;
}

export interface StepUpRequestOptions {
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface StepUpIdempotentRequestOptions extends StepUpRequestOptions {
  idempotencyKey?: string;
}

export class StepUpClient {
  private readonly endpoint: string;
  private readonly http: HttpProvider;

  constructor(config: StepUpClientConfig) {
    this.endpoint = config.endpoint.replace(/\/$/, '');
    this.http = config.http;
  }

  async start(
    request: StepUpStartRequest,
    options?: StepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>('/start', {
      method: 'POST',
      headers: jsonHeaders(options?.headers),
      body: JSON.stringify(request),
      signal: options?.signal,
    });
  }

  async getAction(
    actionId: string,
    options?: StepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(`/actions/${encodeURIComponent(actionId)}`, {
      method: 'GET',
      headers: acceptJsonHeaders(options?.headers),
      signal: options?.signal,
    });
  }

  async complete<Input = unknown>(
    actionId: string,
    request: StepUpCompleteRequest<Input>,
    options?: StepUpIdempotentRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(
      `/actions/${encodeURIComponent(actionId)}/complete`,
      {
        method: 'POST',
        headers: withIdempotencyKey(jsonHeaders(options?.headers), options?.idempotencyKey),
        body: JSON.stringify(request),
        signal: options?.signal,
      }
    );
  }

  async resend(
    actionId: string,
    options?: StepUpIdempotentRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(
      `/actions/${encodeURIComponent(actionId)}/resend`,
      {
        method: 'POST',
        headers: withIdempotencyKey(acceptJsonHeaders(options?.headers), options?.idempotencyKey),
        signal: options?.signal,
      }
    );
  }

  async cancel(
    actionId: string,
    options?: StepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(`/actions/${encodeURIComponent(actionId)}`, {
      method: 'DELETE',
      headers: acceptJsonHeaders(options?.headers),
      signal: options?.signal,
    });
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await this.http.fetch(`${this.endpoint}${path}`, init);
    } catch (error) {
      throw new AuthrimServerError('network_error', 'Step-Up request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const payload = await readOAuthErrorPayload(response);
      throw createServerErrorFromOAuthResponse(
        payload,
        fallbackCodeForStatus(response.status),
        `Step-Up request failed: ${response.status} ${response.statusText}`,
        { status: response.status }
      );
    }

    return await response.json() as T;
  }
}

function acceptJsonHeaders(headers?: HeadersInit): Headers {
  const next = new Headers(headers);
  if (!next.has('Accept')) {
    next.set('Accept', 'application/json');
  }
  return next;
}

function jsonHeaders(headers?: HeadersInit): Headers {
  const next = acceptJsonHeaders(headers);
  if (!next.has('Content-Type')) {
    next.set('Content-Type', 'application/json');
  }
  return next;
}

function withIdempotencyKey(headers: Headers, idempotencyKey?: string): Headers {
  const key = idempotencyKey ?? generateIdempotencyKey();
  validateIdempotencyKey(key);
  headers.set('Idempotency-Key', key);
  return headers;
}

function generateIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `idem_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 18)}`;
}

function validateIdempotencyKey(value: string): void {
  if (value.length < 8 || value.length > 128 || /[\r\n\0]/.test(value)) {
    throw new AuthrimServerError(
      'configuration_error',
      'Idempotency-Key must be 8-128 characters and must not contain control line breaks'
    );
  }
}

function fallbackCodeForStatus(status: number): AuthrimServerErrorCode {
  if (status === 403) {
    return 'step_up_required';
  }
  if (status === 429) {
    return 'resend_limit_exceeded';
  }
  if (status === 409) {
    return 'idempotency_conflict';
  }
  return 'invalid_step_up_input';
}

async function readOAuthErrorPayload(response: Response): Promise<AuthrimOAuthErrorResponse | null> {
  const contentType = response.headers?.get?.('content-type') ?? '';

  if (contentType.includes('json')) {
    try {
      return await response.json() as AuthrimOAuthErrorResponse;
    } catch {
      return null;
    }
  }

  try {
    const text = await response.text();
    if (!text) {
      return null;
    }
    return JSON.parse(text) as AuthrimOAuthErrorResponse;
  } catch {
    return null;
  }
}
