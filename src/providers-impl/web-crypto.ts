/**
 * Web Crypto API Provider Implementation
 *
 * Uses crypto.subtle for cryptographic operations.
 */

import type { CryptoProvider } from '../providers/crypto.js';
import { base64UrlEncode } from '../utils/base64url.js';

/**
 * Algorithm parameters mapping
 */
const ALGORITHM_PARAMS: Record<string, AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams> = {
  // RSA PKCS#1 v1.5
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  RS384: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  RS512: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  // RSA-PSS
  PS256: { name: 'RSA-PSS', hash: 'SHA-256' },
  PS384: { name: 'RSA-PSS', hash: 'SHA-384' },
  PS512: { name: 'RSA-PSS', hash: 'SHA-512' },
  // ECDSA
  ES256: { name: 'ECDSA', namedCurve: 'P-256' },
  ES384: { name: 'ECDSA', namedCurve: 'P-384' },
  ES512: { name: 'ECDSA', namedCurve: 'P-521' },
};

/**
 * Get verification algorithm parameters
 */
function getVerifyParams(alg: string): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  const params = ALGORITHM_PARAMS[alg];
  if (!params) {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  if (alg.startsWith('PS')) {
    // RSA-PSS requires salt length
    const hashLength = { PS256: 32, PS384: 48, PS512: 64 }[alg] ?? 32;
    return { name: 'RSA-PSS', saltLength: hashLength };
  }

  if (alg.startsWith('ES')) {
    const hashName = { ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512' }[alg] ?? 'SHA-256';
    return { name: 'ECDSA', hash: hashName };
  }

  return params;
}

/**
 * Get required key members for thumbprint calculation (RFC 7638)
 */
function getThumbprintMembers(jwk: JsonWebKey): Record<string, unknown> {
  const kty = jwk.kty;

  switch (kty) {
    case 'RSA':
      return { e: jwk.e, kty: jwk.kty, n: jwk.n };
    case 'EC':
      return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
    case 'OKP':
      return { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
    default:
      throw new Error(`Unsupported key type for thumbprint: ${kty}`);
  }
}

/**
 * Create a Web Crypto API-based crypto provider
 *
 * This implementation uses crypto.subtle which is available in:
 * - Node.js 18+
 * - Bun
 * - Deno
 * - Cloudflare Workers
 * - Vercel Edge Functions
 * - All modern browsers
 *
 * @returns CryptoProvider implementation
 */
export function webCryptoProvider(): CryptoProvider {
  const crypto = globalThis.crypto;

  return {
    async verifySignature(
      alg: string,
      key: CryptoKey,
      signature: Uint8Array,
      data: Uint8Array
    ): Promise<boolean> {
      const params = getVerifyParams(alg);
      return crypto.subtle.verify(params, key, signature as BufferSource, data as BufferSource);
    },

    async importJwk(jwk: JsonWebKey, alg: string): Promise<CryptoKey> {
      const params = ALGORITHM_PARAMS[alg];
      if (!params) {
        throw new Error(`Unsupported algorithm: ${alg}`);
      }
      return crypto.subtle.importKey('jwk', jwk, params, true, ['verify']);
    },

    async sha256(data: string | Uint8Array): Promise<Uint8Array> {
      const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
      const hash = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
      return new Uint8Array(hash);
    },

    async calculateThumbprint(jwk: JsonWebKey): Promise<string> {
      // Get required members in lexicographic order (RFC 7638)
      const members = getThumbprintMembers(jwk);
      const json = JSON.stringify(members, Object.keys(members).sort());
      const hash = await this.sha256(json);
      return base64UrlEncode(hash);
    },
  };
}
