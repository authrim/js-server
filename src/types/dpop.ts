/**
 * DPoP Type Definitions (RFC 9449)
 *
 * Demonstrating Proof of Possession at the Application Layer
 */

import type { PublicJwk } from './jwk.js';

/**
 * DPoP proof header (RFC 9449 Section 4.2)
 */
export interface DPoPProofHeader {
  /** Type (must be 'dpop+jwt') */
  typ: 'dpop+jwt';
  /** Algorithm */
  alg: string;
  /** Public key (required in header) */
  jwk: PublicJwk;
}

/**
 * DPoP proof payload (RFC 9449 Section 4.2)
 */
export interface DPoPProofPayload {
  /** Unique identifier (for replay prevention) */
  jti: string;
  /** HTTP method (uppercase) */
  htm: string;
  /** HTTP URI (scheme + authority + path, no query/fragment) */
  htu: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Server-provided nonce (optional) */
  nonce?: string;
  /** Access token hash (optional, for resource requests) */
  ath?: string;
}

/**
 * Parsed DPoP proof
 */
export interface ParsedDPoPProof {
  header: DPoPProofHeader;
  payload: DPoPProofPayload;
  signature: string;
}

/**
 * DPoP validation options
 */
export interface DPoPValidationOptions {
  /** Expected HTTP method */
  method: string;
  /** Expected HTTP URI */
  uri: string;
  /** Access token (for ath validation) */
  accessToken?: string;
  /** Expected JWK thumbprint (from token's cnf.jkt) */
  expectedThumbprint?: string;
  /** Server-provided nonce to validate */
  expectedNonce?: string;
  /** Maximum age for iat claim (seconds, default: 60) */
  maxAge?: number;
  /** Clock tolerance (seconds, default: 60) */
  clockTolerance?: number;
}

/**
 * DPoP validation result
 */
export interface DPoPValidationResult {
  /** Whether validation succeeded */
  valid: boolean;
  /** JWK thumbprint of the proof key */
  thumbprint?: string;
  /** Error code if validation failed */
  errorCode?: string;
  /** Error message if validation failed */
  errorMessage?: string;
}

/**
 * URI normalization options
 */
export interface UriNormalizationOptions {
  /** Whether to include the port in the URI (default: only non-standard ports) */
  includePort?: boolean;
}
