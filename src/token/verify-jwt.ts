/**
 * JWT Signature Verification
 *
 * RFC 7519 - JSON Web Token (JWT)
 *
 * This module handles ONLY cryptographic signature verification.
 * Claims validation is handled separately in validate-claims.ts.
 */

import type { CryptoProvider } from '../providers/crypto.js';
import type { JwtHeader, ParsedJwt } from '../types/claims.js';
import { base64UrlDecode, base64UrlDecodeString } from '../utils/base64url.js';

/**
 * Maximum JWT size in bytes (8KB)
 * This prevents DoS attacks using extremely large tokens
 */
const MAX_JWT_SIZE = 8192;

/**
 * Supported signing algorithms
 */
const SUPPORTED_ALGORITHMS = new Set([
  'RS256', 'RS384', 'RS512',  // RSASSA-PKCS1-v1_5
  'PS256', 'PS384', 'PS512',  // RSASSA-PSS
  'ES256', 'ES384', 'ES512',  // ECDSA
  'EdDSA',                     // Edwards-curve
]);

/**
 * Error class for insecure algorithm (alg: none) rejection
 *
 * Thrown when a JWT uses alg: none, which is a critical security issue.
 * This allows callers to distinguish this specific error for logging purposes.
 */
export class InsecureAlgorithmError extends Error {
  readonly code = 'insecure_algorithm' as const;

  constructor() {
    super('Algorithm "none" is not allowed');
    this.name = 'InsecureAlgorithmError';
  }
}

/**
 * Parse a JWT without verification
 *
 * @param token - JWT string
 * @returns Parsed JWT structure
 * @throws Error if JWT format is invalid
 * @throws InsecureAlgorithmError if JWT uses alg: none
 */
export function parseJwt<T = Record<string, unknown>>(token: string): ParsedJwt<T> {
  // Check size to prevent DoS attacks with huge payloads
  if (token.length > MAX_JWT_SIZE) {
    throw new Error(`JWT exceeds maximum size of ${MAX_JWT_SIZE} bytes`);
  }

  const parts = token.split('.');

  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 parts');
  }

  const [headerPart, payloadPart, signaturePart] = parts;

  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error('Invalid JWT format: empty parts');
  }

  try {
    const headerRaw = JSON.parse(base64UrlDecodeString(headerPart));
    const payload = JSON.parse(base64UrlDecodeString(payloadPart)) as T;

    // Validate header structure
    if (!headerRaw || typeof headerRaw !== 'object') {
      throw new Error('Invalid JWT header: must be an object');
    }

    // Validate alg claim exists and is a string
    if (typeof headerRaw.alg !== 'string') {
      throw new Error('Invalid JWT header: missing or invalid alg claim');
    }

    // Explicitly reject "none" algorithm (and case variations) - critical security check
    // This prevents algorithm substitution attacks
    if (headerRaw.alg.toLowerCase() === 'none') {
      throw new InsecureAlgorithmError();
    }

    const header = headerRaw as JwtHeader;

    return {
      header,
      payload,
      signature: signaturePart,
    };
  } catch (error) {
    // Re-throw InsecureAlgorithmError as-is for security logging
    if (error instanceof InsecureAlgorithmError) {
      throw error;
    }
    // Return generic error message to avoid information leakage for other errors
    throw new Error('Invalid JWT format');
  }
}

/**
 * Verify JWT signature
 *
 * @param token - JWT string
 * @param key - CryptoKey for verification
 * @param crypto - Crypto provider
 * @returns Parsed JWT if signature is valid, null otherwise
 */
export async function verifyJwtSignature<T = Record<string, unknown>>(
  token: string,
  key: CryptoKey,
  crypto: CryptoProvider
): Promise<ParsedJwt<T> | null> {
  // Parse JWT
  const parsed = parseJwt<T>(token);

  // Validate algorithm
  if (!SUPPORTED_ALGORITHMS.has(parsed.header.alg)) {
    return null;
  }

  // Extract signing input and signature
  const dotIndex = token.lastIndexOf('.');
  const signingInput = token.substring(0, dotIndex);
  const signatureBytes = base64UrlDecode(parsed.signature);

  // Verify signature
  const data = new TextEncoder().encode(signingInput);
  const valid = await crypto.verifySignature(
    parsed.header.alg,
    key,
    signatureBytes,
    data
  );

  return valid ? parsed : null;
}

/**
 * Get signing input from JWT (header.payload)
 *
 * @param token - JWT string
 * @returns Signing input as bytes
 */
export function getSigningInput(token: string): Uint8Array {
  const dotIndex = token.lastIndexOf('.');
  const signingInput = token.substring(0, dotIndex);
  return new TextEncoder().encode(signingInput);
}

/**
 * Get signature from JWT
 *
 * @param token - JWT string
 * @returns Signature as bytes
 */
export function getSignature(token: string): Uint8Array {
  const dotIndex = token.lastIndexOf('.');
  const signatureB64 = token.substring(dotIndex + 1);
  return base64UrlDecode(signatureB64);
}
