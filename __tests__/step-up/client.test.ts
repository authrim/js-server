import { describe, expect, it, vi } from 'vitest';
import {
  AuthrimServer,
  AuthrimServerError,
  DEFAULT_STEP_UP_POLICY,
  StepUpClient,
} from '../../src/index.js';
import type { HttpProvider } from '../../src/providers/http.js';

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers instanceof Headers ? Object.fromEntries(init.headers.entries()) : init?.headers),
    },
  });
}

function createServer(http: HttpProvider, stepUpEndpoint?: string): AuthrimServer {
  return new AuthrimServer({
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    jwksUri: 'https://auth.example.com/.well-known/jwks.json',
    stepUpEndpoint,
    http,
  });
}

describe('StepUpClient', () => {
  it('starts actions through the canonical endpoint', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse({
        action_id: 'sua_123',
        status: 'pending',
        preferred_method: { method: 'email_otp', category: 'otp' },
      })),
    };
    const server = createServer(http);

    const result = await server.startStepUp({
      step_up_token: 'stu_123',
      preferred_method: 'email_otp',
    });

    expect(result.action_id).toBe('sua_123');
    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/auth/step-up/start',
      expect.objectContaining({ method: 'POST' })
    );
    const init = (http.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit;
    expect((init.headers as Headers).get('Content-Type')).toBe('application/json');
    expect(JSON.parse(init.body as string)).toEqual({
      step_up_token: 'stu_123',
      preferred_method: 'email_otp',
    });
  });

  it('uses explicit stepUpEndpoint overrides', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse({
        action_id: 'sua_123',
        status: 'pending',
      })),
    };
    const server = createServer(http, 'https://stepup.example.com/custom');

    await server.stepUp.start({ step_up_token: 'stu_123' });

    expect(server.getConfig().stepUpEndpoint).toBe('https://stepup.example.com/custom');
    expect(http.fetch).toHaveBeenCalledWith(
      'https://stepup.example.com/custom/start',
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('completes actions with an idempotency key and receipt typing', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse({
        action_id: 'sua_123',
        status: 'completed',
        step_up_receipt: 'sur_123',
      })),
    };
    const client = new StepUpClient({
      endpoint: 'https://auth.example.com/auth/step-up',
      http,
    });

    const result = await client.complete(
      'sua_123',
      { input: { code: '123456' } },
      { idempotencyKey: 'idem-12345678' }
    );

    expect(result.step_up_receipt).toBe('sur_123');
    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/auth/step-up/actions/sua_123/complete',
      expect.objectContaining({ method: 'POST' })
    );
    const init = (http.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit;
    expect((init.headers as Headers).get('Idempotency-Key')).toBe('idem-12345678');
  });

  it('generates idempotency keys for resend when omitted', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse({
        action_id: 'sua_123',
        status: 'pending',
      })),
    };
    const client = new StepUpClient({
      endpoint: 'https://auth.example.com/auth/step-up',
      http,
    });

    await client.resend('sua_123');

    const init = (http.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit;
    const key = (init.headers as Headers).get('Idempotency-Key');
    expect(key).toEqual(expect.any(String));
    expect(key?.length).toBeGreaterThanOrEqual(8);
  });

  it('preserves machine-readable Step-Up errors', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse(
        {
          error: 'invalid_step_up_input',
          error_description: 'Invalid verification code',
          error_details: {
            code: 'invalid_step_up_input',
            retryable: true,
            severity: 'warning',
            field: 'code',
          },
          status: {
            action_id: 'sua_123',
            status: 'pending',
            method: 'email_otp',
            category: 'otp',
            updated_at: '2026-05-05T00:00:00.000Z',
            updated_at_unix: 1777939200,
          },
          input_state: {
            field: 'code',
            attempts_remaining: 4,
          },
        },
        { status: 400, statusText: 'Bad Request' }
      )),
    };
    const client = new StepUpClient({
      endpoint: 'https://auth.example.com/auth/step-up',
      http,
    });

    await expect(
      client.complete('sua_123', { input: { code: '000000' } }, { idempotencyKey: 'idem-12345678' })
    ).rejects.toMatchObject({
      code: 'invalid_step_up_input',
      message: 'Invalid verification code',
      details: expect.objectContaining({
        errorDetails: expect.objectContaining({ field: 'code' }),
        status: expect.objectContaining({
          action_id: 'sua_123',
          method: 'email_otp',
          category: 'otp',
        }),
        inputState: expect.objectContaining({ attempts_remaining: 4 }),
      }),
    });
  });

  it('rejects invalid explicit idempotency keys before sending', async () => {
    const http: HttpProvider = {
      fetch: vi.fn(),
    };
    const client = new StepUpClient({
      endpoint: 'https://auth.example.com/auth/step-up',
      http,
    });

    await expect(
      client.resend('sua_123', { idempotencyKey: 'bad\nkey' })
    ).rejects.toBeInstanceOf(AuthrimServerError);
    expect(http.fetch).not.toHaveBeenCalled();
  });

  it('exports canonical default policy values', () => {
    expect(DEFAULT_STEP_UP_POLICY).toEqual({
      token_ttl_seconds: 300,
      action_ttl_seconds: 600,
      receipt_ttl_seconds: 300,
      max_attempts: 5,
      resend_cooldown_seconds: 60,
      max_resends: 3,
    });
  });
});
