/**
 * JWK (JSON Web Key) Type Definitions
 *
 * Based on RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms)
 */

/**
 * Key type (RFC 7517 Section 6.1)
 */
export type JwkKeyType = 'EC' | 'RSA' | 'oct' | 'OKP';

/**
 * Key use (RFC 7517 Section 4.2)
 */
export type JwkKeyUse = 'sig' | 'enc';

/**
 * Key operations (RFC 7517 Section 4.3)
 */
export type JwkKeyOps = 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey' | 'deriveBits';

/**
 * Supported signing algorithms (RFC 7518)
 */
export type JwkSigningAlgorithm =
  | 'RS256' | 'RS384' | 'RS512'   // RSASSA-PKCS1-v1_5
  | 'PS256' | 'PS384' | 'PS512'   // RSASSA-PSS
  | 'ES256' | 'ES384' | 'ES512'   // ECDSA
  | 'EdDSA';                       // Edwards-curve Digital Signature Algorithm

/**
 * EC curve names (RFC 7518 Section 6.2.1.1)
 */
export type EcCurve = 'P-256' | 'P-384' | 'P-521';

/**
 * OKP curve names (RFC 8037)
 */
export type OkpCurve = 'Ed25519' | 'Ed448' | 'X25519' | 'X448';

/**
 * Base JWK properties (RFC 7517 Section 4)
 */
export interface JwkBase {
  /** Key Type (required) */
  kty: JwkKeyType;
  /** Public Key Use */
  use?: JwkKeyUse;
  /** Key Operations */
  key_ops?: JwkKeyOps[];
  /** Algorithm */
  alg?: JwkSigningAlgorithm;
  /** Key ID */
  kid?: string;
  /** X.509 URL */
  x5u?: string;
  /** X.509 Certificate Chain */
  x5c?: string[];
  /** X.509 Certificate SHA-1 Thumbprint */
  x5t?: string;
  /** X.509 Certificate SHA-256 Thumbprint */
  'x5t#S256'?: string;
}

/**
 * RSA Public Key (RFC 7518 Section 6.3)
 */
export interface RsaPublicJwk extends JwkBase {
  kty: 'RSA';
  /** Modulus */
  n: string;
  /** Exponent */
  e: string;
}

/**
 * EC Public Key (RFC 7518 Section 6.2)
 */
export interface EcPublicJwk extends JwkBase {
  kty: 'EC';
  /** Curve */
  crv: EcCurve;
  /** X Coordinate */
  x: string;
  /** Y Coordinate */
  y: string;
}

/**
 * OKP (Octet Key Pair) Public Key (RFC 8037)
 */
export interface OkpPublicJwk extends JwkBase {
  kty: 'OKP';
  /** Curve */
  crv: OkpCurve;
  /** Public Key */
  x: string;
}

/**
 * Public JWK (union type)
 */
export type PublicJwk = RsaPublicJwk | EcPublicJwk | OkpPublicJwk;

/**
 * JWK Set (RFC 7517 Section 5)
 */
export interface JwkSet {
  keys: PublicJwk[];
}

/**
 * Internal representation of a cached JWK with metadata
 */
export interface CachedJwk {
  jwk: PublicJwk;
  cryptoKey: CryptoKey;
}
