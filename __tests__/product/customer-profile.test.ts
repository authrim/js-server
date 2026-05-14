import { describe, expect, it, vi } from 'vitest';
import { AuthrimServer, CustomerProfileClient } from '../../src/index.js';
import type { HttpProvider } from '../../src/providers/http.js';

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'content-type': 'application/json' },
  });
}

describe('CustomerProfileClient', () => {
  it('sends delegated writes through the standard actor-preserving route', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse({
        customer_profile: { sub: 'user-1', name: 'Alice Updated' },
      })),
    };
    const client = new CustomerProfileClient({
      issuer: 'https://auth.example.com',
      http,
    });

    await client.updateDelegated(
      'user-1',
      { name: 'Alice Updated' },
      {
        accessToken: 'actor-token',
        stepUpReceipt: 'sur_receipt_123',
        idempotencyKey: 'delegated-key-1',
        audit: { reason_code: 'admin_repair' },
        include: ['actor', 'subject'],
      }
    );

    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/api/protected/customer-profiles/users/user-1?include=actor%2Csubject',
      expect.objectContaining({ method: 'PATCH' })
    );
    const init = (http.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as RequestInit;
    expect((init.headers as Headers).get('Authorization')).toBe('Bearer actor-token');
    expect((init.headers as Headers).get('Authrim-Step-Up-Receipt')).toBe('sur_receipt_123');
    expect((init.headers as Headers).get('Idempotency-Key')).toBe('delegated-key-1');
    expect(JSON.parse(init.body as string)).toEqual({
      input: { name: 'Alice Updated' },
      audit: { reason_code: 'admin_repair' },
    });
  });

  it('keeps downstream elevation reads on the product-specific route', async () => {
    const http: HttpProvider = {
      fetch: vi.fn().mockResolvedValue(jsonResponse({
        profile: { sub: 'user-1' },
      })),
    };
    const server = new AuthrimServer({
      issuer: 'https://auth.example.com',
      audience: 'https://api.example.com',
      jwksUri: 'https://auth.example.com/.well-known/jwks.json',
      http,
    });

    await server.customerProfiles.getWithElevationGrant('user-1', {
      accessToken: 'elevation-token',
    });

    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/api/protected/customer-profiles/user-1',
      expect.objectContaining({ method: 'GET' })
    );
  });
});
