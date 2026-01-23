/**
 * Credential Issuer (OpenID4VCI)
 *
 * OpenID for Verifiable Credential Issuance
 */

import type { HttpProvider } from '../providers/http.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type {
  CredentialRequest,
  CredentialResponse,
  CredentialOffer,
  CredentialFormat,
} from './types.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * Credential Issuer configuration
 */
export interface CredentialIssuerConfig {
  /** Credential issuer URL */
  issuerUrl: string;
  /** HTTP provider */
  http: HttpProvider;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Access token */
  accessToken: string;
}

/**
 * Credential issuer metadata
 */
export interface CredentialIssuerMetadata {
  credential_issuer: string;
  credential_endpoint: string;
  credential_configurations_supported: Record<string, {
    format: CredentialFormat;
    scope?: string;
    cryptographic_binding_methods_supported?: string[];
    proof_types_supported?: Record<string, unknown>;
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

/**
 * Credential Issuer Client
 *
 * Provides methods for requesting credentials from an issuer.
 */
export class CredentialIssuer {
  private readonly config: CredentialIssuerConfig;
  private metadata: CredentialIssuerMetadata | null = null;

  constructor(config: CredentialIssuerConfig) {
    this.config = config;
  }

  /**
   * Discover issuer metadata
   */
  async discover(): Promise<CredentialIssuerMetadata> {
    if (this.metadata) {
      return this.metadata;
    }

    const url = `${this.config.issuerUrl.replace(/\/$/, '')}/.well-known/openid-credential-issuer`;

    try {
      const response = await this.config.http.fetch(url, {
        headers: { Accept: 'application/json' },
      });

      if (!response.ok) {
        throw new AuthrimServerError(
          'configuration_error',
          `Failed to fetch issuer metadata: ${response.status}`
        );
      }

      this.metadata = await response.json() as CredentialIssuerMetadata;
      return this.metadata;
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }
      throw new AuthrimServerError(
        'configuration_error',
        `Failed to discover issuer: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Request a credential
   */
  async requestCredential(request: CredentialRequest): Promise<CredentialResponse> {
    const metadata = await this.discover();

    try {
      const response = await this.config.http.fetch(metadata.credential_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.accessToken}`,
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new AuthrimServerError(
          'network_error',
          `Credential request failed: ${response.status}`,
          { details: error as Record<string, unknown> }
        );
      }

      return response.json() as Promise<CredentialResponse>;
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }
      throw new AuthrimServerError(
        'network_error',
        `Credential request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Parse a credential offer URI
   */
  static parseCredentialOfferUri(uri: string): CredentialOffer {
    const url = new URL(uri);
    const offerParam = url.searchParams.get('credential_offer');
    const offerUriParam = url.searchParams.get('credential_offer_uri');

    if (offerParam) {
      return JSON.parse(offerParam) as CredentialOffer;
    }

    if (offerUriParam) {
      throw new AuthrimServerError(
        'configuration_error',
        'credential_offer_uri requires fetching - use parseCredentialOfferUriAsync'
      );
    }

    throw new AuthrimServerError(
      'configuration_error',
      'Invalid credential offer URI'
    );
  }
}
