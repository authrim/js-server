import type { HttpProvider } from '../providers/http.js';
import {
  AuthrimServerError,
  createServerErrorFromOAuthResponse,
  type AuthrimOAuthErrorResponse,
} from '../types/errors.js';
import { readResponseJsonWithLimit } from '../utils/response-limits.js';

const MAX_CUSTOMER_PROFILE_RESPONSE_BYTES = 256 * 1024;
const MAX_CUSTOMER_PROFILE_ERROR_BYTES = 16 * 1024;

export interface DelegatedWriteAudit {
  reason_code?: string;
  reason_note?: string;
  reference_id?: string;
}

export interface CustomerProfileUpdateInput {
  email?: string;
  phone_number?: string | null;
  name?: string | null;
  given_name?: string | null;
  family_name?: string | null;
  nickname?: string | null;
  preferred_username?: string | null;
  picture?: string | null;
  website?: string | null;
  gender?: string | null;
  birthdate?: string | null;
  locale?: string | null;
  zoneinfo?: string | null;
  address?: Record<string, string | null | undefined> | null;
}

export interface CustomerProfileView {
  sub: string;
  [key: string]: unknown;
}

export interface CustomerProfileDelegatedWriteResponse {
  customer_profile: CustomerProfileView;
  actor?: { id: string };
  subject?: { id: string };
  audit?: DelegatedWriteAudit;
}

export interface CustomerProfileElevationReadResponse {
  profile: CustomerProfileView;
  correlation_id?: string;
  redaction_level?: string;
  requires_online_check?: boolean;
  fail_closed?: boolean;
}

export interface CustomerProfileClientConfig {
  issuer: string;
  http: HttpProvider;
}

export interface CustomerProfileRequestOptions {
  accessToken: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export interface CustomerProfileDelegatedWriteOptions extends CustomerProfileRequestOptions {
  stepUpReceipt: string;
  idempotencyKey?: string;
  audit?: DelegatedWriteAudit;
  include?: Array<'actor' | 'subject' | 'audit'>;
}

export class CustomerProfileClient {
  private readonly issuer: string;
  private readonly http: HttpProvider;

  constructor(config: CustomerProfileClientConfig) {
    this.issuer = config.issuer.replace(/\/$/, '');
    this.http = config.http;
  }

  async getWithElevationGrant(
    subjectUserId: string,
    options: CustomerProfileRequestOptions
  ): Promise<CustomerProfileElevationReadResponse> {
    return this.request(
      `/api/protected/customer-profiles/${encodeURIComponent(subjectUserId)}`,
      {
        method: 'GET',
        headers: bearerHeaders(options.accessToken, options.headers),
        signal: options.signal,
      }
    );
  }

  async updateDelegated(
    subjectUserId: string,
    input: CustomerProfileUpdateInput,
    options: CustomerProfileDelegatedWriteOptions
  ): Promise<CustomerProfileDelegatedWriteResponse> {
    const query = options.include?.length
      ? `?include=${encodeURIComponent(options.include.join(','))}`
      : '';
    const headers = bearerHeaders(options.accessToken, options.headers);
    headers.set('Content-Type', 'application/json');
    headers.set('Authrim-Step-Up-Receipt', assertHeaderValue(options.stepUpReceipt, 'stepUpReceipt'));
    headers.set(
      'Idempotency-Key',
      options.idempotencyKey
        ? assertHeaderValue(options.idempotencyKey, 'idempotencyKey')
        : createIdempotencyKey()
    );

    return this.request(
      `/api/protected/customer-profiles/users/${encodeURIComponent(subjectUserId)}${query}`,
      {
        method: 'PATCH',
        headers,
        body: JSON.stringify({
          input,
          ...(options.audit ? { audit: options.audit } : {}),
        }),
        signal: options.signal,
      }
    );
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await this.http.fetch(`${this.issuer}${path}`, init);
    } catch (error) {
      throw new AuthrimServerError('network_error', 'Customer profile request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const payload = await readJson(response);
      throw createServerErrorFromOAuthResponse(
        payload,
        response.status === 403 ? 'step_up_required' : 'invalid_token',
        `Customer profile request failed: ${response.status} ${response.statusText}`,
        { status: response.status }
      );
    }

    return await readResponseJsonWithLimit<T>(response, MAX_CUSTOMER_PROFILE_RESPONSE_BYTES);
  }
}

function bearerHeaders(accessToken: string, headers?: HeadersInit): Headers {
  const token = accessToken.trim();
  if (!token) {
    throw new AuthrimServerError('configuration_error', 'accessToken is required');
  }
  const next = new Headers(headers);
  next.set('Authorization', `Bearer ${token}`);
  next.set('Accept', 'application/json');
  return next;
}

function assertHeaderValue(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized.length < 8 || normalized.length > 256 || /[\r\n\0]/.test(normalized)) {
    throw new AuthrimServerError('configuration_error', `${name} is invalid`);
  }
  return normalized;
}

function createIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }

  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new AuthrimServerError('configuration_error', 'Secure random generation is unavailable');
  }

  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const randomHex = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
  return `idem_${randomHex}`;
}

async function readJson(response: Response): Promise<AuthrimOAuthErrorResponse | null> {
  try {
    return await readResponseJsonWithLimit<Record<string, unknown>>(
      response,
      MAX_CUSTOMER_PROFILE_ERROR_BYTES
    );
  } catch {
    return null;
  }
}
