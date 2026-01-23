/**
 * DPoP Proof Validator (RFC 9449)
 *
 * IMPORTANT: This SDK validates DPoP proofs STATELESSLY.
 *
 * What this SDK validates:
 * - Proof signature (embedded JWK in header)
 * - htm (HTTP method) matches request
 * - htu (HTTP URI) matches request
 * - ath (access token hash) if present
 * - cnf.jkt binding (thumbprint matches)
 * - iat is within acceptable window
 *
 * What this SDK does NOT validate:
 * - jti uniqueness (replay detection)
 *   → MUST be implemented by the resource server if required
 *   → Recommended: Store jti with TTL = proof lifetime + clock tolerance
 *
 * Nonce handling:
 * - If server returns use_dpop_nonce error, SDK returns dpop_nonce_required
 * - Application is responsible for retry with nonce
 */

import type { CryptoProvider } from '../providers/crypto.js';
import type { ClockProvider } from '../providers/clock.js';
import type { DPoPProofHeader, DPoPProofPayload, DPoPValidationOptions, DPoPValidationResult } from '../types/dpop.js';
import { base64UrlDecode, base64UrlDecodeString, base64UrlEncode } from '../utils/base64url.js';
import { timingSafeEqual } from '../utils/timing-safe.js';
import { calculateJwkThumbprint } from './thumbprint.js';

/**
 * Supported algorithms for DPoP proofs
 */
const SUPPORTED_ALGORITHMS = new Set([
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
]);

/**
 * Private key parameters that MUST NOT be present in DPoP proof JWK
 * Per RFC 9449, the JWK in the header MUST be a public key
 */
const PRIVATE_KEY_PARAMS = new Set([
  'd',   // EC/OKP private key, RSA private exponent
  'p',   // RSA first prime factor
  'q',   // RSA second prime factor
  'dp',  // RSA first factor CRT exponent
  'dq',  // RSA second factor CRT exponent
  'qi',  // RSA first CRT coefficient
  'k',   // Symmetric key (should not appear in asymmetric JWKs anyway)
]);

/**
 * Parse a DPoP proof without verification
 */
function parseDPoPProof(proof: string): { header: DPoPProofHeader; payload: DPoPProofPayload; signature: string } {
  const parts = proof.split('.');

  if (parts.length !== 3) {
    throw new Error('Invalid DPoP proof format: expected 3 parts');
  }

  const [headerPart, payloadPart, signaturePart] = parts;

  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error('Invalid DPoP proof format: empty parts');
  }

  const header = JSON.parse(base64UrlDecodeString(headerPart)) as DPoPProofHeader;
  const payload = JSON.parse(base64UrlDecodeString(payloadPart)) as DPoPProofPayload;

  return { header, payload, signature: signaturePart };
}

/**
 * Normalize URI for htu comparison
 *
 * Per RFC 9449, the htu claim contains the scheme, host, and path,
 * but NOT the query string or fragment.
 *
 * @returns Normalized URI or null if URI is invalid
 */
function normalizeUri(uri: string): string | null {
  try {
    const url = new URL(uri);
    // Return scheme + host + path (no query or fragment)
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    // Return null for invalid URIs instead of silently passing through
    return null;
  }
}

/**
 * DPoP Proof Validator
 */
export class DPoPValidator {
  constructor(
    private readonly crypto: CryptoProvider,
    private readonly clock: ClockProvider
  ) {}

  /**
   * Validate a DPoP proof
   *
   * @param proof - DPoP proof JWT
   * @param options - Validation options
   * @returns Validation result
   */
  async validate(
    proof: string,
    options: DPoPValidationOptions
  ): Promise<DPoPValidationResult> {
    try {
      // Parse proof
      const { header, payload } = parseDPoPProof(proof);

      // Validate header
      const headerResult = this.validateHeader(header);
      if (!headerResult.valid) {
        return headerResult;
      }

      // Validate payload structure
      const payloadResult = this.validatePayloadStructure(payload);
      if (!payloadResult.valid) {
        return payloadResult;
      }

      // Verify signature
      const signatureResult = await this.verifySignature(proof, header);
      if (!signatureResult.valid) {
        return signatureResult;
      }

      // Validate htm (HTTP method)
      if (payload.htm.toUpperCase() !== options.method.toUpperCase()) {
        return {
          valid: false,
          errorCode: 'dpop_method_mismatch',
          errorMessage: `Method mismatch: expected ${options.method}, got ${payload.htm}`,
        };
      }

      // Validate htu (HTTP URI)
      const expectedUri = normalizeUri(options.uri);
      const actualUri = normalizeUri(payload.htu);

      // Reject if either URI is invalid
      if (expectedUri === null) {
        return {
          valid: false,
          errorCode: 'dpop_proof_invalid',
          errorMessage: `Invalid expected URI: ${options.uri}`,
        };
      }
      if (actualUri === null) {
        return {
          valid: false,
          errorCode: 'dpop_uri_mismatch',
          errorMessage: `Invalid htu claim: ${payload.htu}`,
        };
      }

      if (expectedUri !== actualUri) {
        return {
          valid: false,
          errorCode: 'dpop_uri_mismatch',
          errorMessage: `URI mismatch: expected ${expectedUri}, got ${actualUri}`,
        };
      }

      // Validate iat (issued at)
      const maxAge = options.maxAge ?? 60;
      const tolerance = options.clockTolerance ?? 60;
      const now = this.clock.nowSeconds();
      const iatMin = now - maxAge - tolerance;
      const iatMax = now + tolerance;

      if (payload.iat < iatMin || payload.iat > iatMax) {
        return {
          valid: false,
          errorCode: 'dpop_iat_expired',
          errorMessage: `Proof iat is outside acceptable window`,
        };
      }

      // Validate nonce if expected
      if (options.expectedNonce !== undefined) {
        if (payload.nonce !== options.expectedNonce) {
          return {
            valid: false,
            errorCode: 'dpop_nonce_required',
            errorMessage: 'Invalid or missing DPoP nonce',
          };
        }
      }

      // Calculate thumbprint
      const thumbprint = await calculateJwkThumbprint(header.jwk as JsonWebKey, this.crypto);

      // Validate access token hash if provided
      if (options.accessToken) {
        const athResult = await this.validateAccessTokenHash(
          payload.ath,
          options.accessToken
        );
        if (!athResult.valid) {
          return athResult;
        }
      }

      // Validate thumbprint binding if expected
      // Use timing-safe comparison to prevent timing attacks
      if (options.expectedThumbprint) {
        if (!timingSafeEqual(thumbprint, options.expectedThumbprint)) {
          return {
            valid: false,
            errorCode: 'dpop_binding_mismatch',
            errorMessage: 'DPoP proof key does not match token binding',
          };
        }
      }

      return {
        valid: true,
        thumbprint,
      };
    } catch (error) {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: error instanceof Error ? error.message : 'Invalid DPoP proof',
      };
    }
  }

  /**
   * Validate DPoP header
   */
  private validateHeader(header: DPoPProofHeader): DPoPValidationResult {
    // Check typ
    if (header.typ !== 'dpop+jwt') {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: 'Invalid DPoP proof type: must be dpop+jwt',
      };
    }

    // Check alg
    if (!SUPPORTED_ALGORITHMS.has(header.alg)) {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: `Unsupported algorithm: ${header.alg}`,
      };
    }

    // Check jwk presence
    if (!header.jwk) {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: 'Missing JWK in DPoP proof header',
      };
    }

    // Check that JWK is a public key (no private key parameters)
    // Per RFC 9449 Section 4.2: The JWK MUST NOT contain a private key
    const jwkObj = header.jwk as unknown as Record<string, unknown>;
    for (const param of PRIVATE_KEY_PARAMS) {
      if (param in jwkObj && jwkObj[param] !== undefined) {
        return {
          valid: false,
          errorCode: 'dpop_proof_invalid',
          errorMessage: 'DPoP proof JWK contains private key parameters',
        };
      }
    }

    return { valid: true };
  }

  /**
   * Validate DPoP payload structure
   */
  private validatePayloadStructure(payload: DPoPProofPayload): DPoPValidationResult {
    if (!payload.jti) {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: 'Missing jti claim',
      };
    }

    if (!payload.htm) {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: 'Missing htm claim',
      };
    }

    if (!payload.htu) {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: 'Missing htu claim',
      };
    }

    if (typeof payload.iat !== 'number') {
      return {
        valid: false,
        errorCode: 'dpop_proof_invalid',
        errorMessage: 'Missing or invalid iat claim',
      };
    }

    return { valid: true };
  }

  /**
   * Verify DPoP proof signature
   */
  private async verifySignature(
    proof: string,
    header: DPoPProofHeader
  ): Promise<DPoPValidationResult> {
    try {
      // Import public key from header
      const cryptoKey = await this.crypto.importJwk(
        header.jwk as JsonWebKey,
        header.alg
      );

      // Get signing input and signature
      const dotIndex = proof.lastIndexOf('.');
      const signingInput = proof.substring(0, dotIndex);
      const signatureB64 = proof.substring(dotIndex + 1);

      const data = new TextEncoder().encode(signingInput);
      const signature = base64UrlDecode(signatureB64);

      // Verify
      const valid = await this.crypto.verifySignature(
        header.alg,
        cryptoKey,
        signature,
        data
      );

      if (!valid) {
        return {
          valid: false,
          errorCode: 'dpop_proof_signature_invalid',
          errorMessage: 'DPoP proof signature verification failed',
        };
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        errorCode: 'dpop_proof_signature_invalid',
        errorMessage: `Failed to verify DPoP proof: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Validate access token hash (ath claim)
   *
   * Per RFC 9449 Section 4.2:
   * When the DPoP proof is used with an access token, the ath claim MUST be present
   * and contain the base64url-encoded SHA-256 hash of the access token.
   */
  private async validateAccessTokenHash(
    ath: string | undefined,
    accessToken: string
  ): Promise<DPoPValidationResult> {
    // When an access token is provided, ath is REQUIRED
    if (!ath) {
      return {
        valid: false,
        errorCode: 'dpop_ath_missing',
        errorMessage: 'Missing ath claim when access token is present',
      };
    }

    // Compute expected hash
    const tokenBytes = new TextEncoder().encode(accessToken);
    const hash = await this.crypto.sha256(tokenBytes);
    const expectedAth = base64UrlEncode(hash);

    // Use timing-safe comparison for defense in depth
    if (!timingSafeEqual(ath, expectedAth)) {
      return {
        valid: false,
        errorCode: 'dpop_ath_mismatch',
        errorMessage: 'Access token hash mismatch',
      };
    }

    return { valid: true };
  }
}
