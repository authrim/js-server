/**
 * Presentation Verifier (OpenID4VP)
 *
 * OpenID for Verifiable Presentations
 */

import type { CryptoProvider } from '../providers/crypto.js';
import type { ClockProvider } from '../providers/clock.js';
import type {
  AuthorizationRequest,
  AuthorizationResponse,
  PresentationDefinition,
  PresentationSubmission,
  VerifiablePresentation,
} from './types.js';

/**
 * Presentation Verifier configuration
 */
export interface PresentationVerifierConfig {
  /** Client ID (verifier identifier) */
  clientId: string;
  /** Redirect URI */
  redirectUri: string;
  /** Crypto provider */
  crypto: CryptoProvider;
  /** Clock provider */
  clock: ClockProvider;
}

/**
 * Presentation verification result
 */
export interface PresentationVerificationResult {
  valid: boolean;
  presentation?: VerifiablePresentation;
  submission?: PresentationSubmission;
  error?: string;
}

/**
 * Presentation Verifier
 *
 * Creates and verifies presentation requests.
 */
export class PresentationVerifier {
  private readonly config: PresentationVerifierConfig;

  constructor(config: PresentationVerifierConfig) {
    this.config = config;
  }

  /**
   * Create an authorization request
   */
  createAuthorizationRequest(
    presentationDefinition: PresentationDefinition,
    options?: {
      state?: string;
      nonce?: string;
    }
  ): AuthorizationRequest {
    const nonce = options?.nonce ?? this.generateNonce();

    return {
      response_type: 'vp_token',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      presentation_definition: presentationDefinition,
      nonce,
      state: options?.state,
    };
  }

  /**
   * Create an authorization request URI
   */
  createAuthorizationRequestUri(
    baseUri: string,
    presentationDefinition: PresentationDefinition,
    options?: {
      state?: string;
      nonce?: string;
    }
  ): string {
    const request = this.createAuthorizationRequest(presentationDefinition, options);
    const url = new URL(baseUri);

    url.searchParams.set('response_type', request.response_type);
    url.searchParams.set('client_id', request.client_id);
    url.searchParams.set('redirect_uri', request.redirect_uri);
    url.searchParams.set('presentation_definition', JSON.stringify(request.presentation_definition));
    url.searchParams.set('nonce', request.nonce);

    if (request.state) {
      url.searchParams.set('state', request.state);
    }

    return url.toString();
  }

  /**
   * Verify an authorization response
   *
   * **IMPORTANT: This is a basic/experimental implementation.**
   *
   * Current implementation only validates:
   * - VP token JWT structure (3 parts)
   *
   * Production deployments MUST implement additional verification:
   * - VP token signature verification
   * - Each credential's signature verification
   * - Credential status (revocation) checking
   * - Holder binding validation
   * - Nonce validation
   * - presentation_submission against presentation_definition validation
   *
   * These features will be fully implemented when @authrim/vc is
   * split into a separate package.
   *
   * @param response - Authorization response containing vp_token
   * @param expectedNonce - Expected nonce value (currently unused - to be implemented)
   * @returns Verification result
   */
  async verifyAuthorizationResponse(
    response: AuthorizationResponse,
    expectedNonce: string
  ): Promise<PresentationVerificationResult> {
    try {
      // Parse VP token (assuming JWT format)
      const vpToken = response.vp_token;

      // Basic JWT structure validation
      const parts = vpToken.split('.');
      if (parts.length !== 3) {
        return {
          valid: false,
          error: 'Invalid VP token format: expected 3 parts (header.payload.signature)',
        };
      }

      // Parse payload to extract nonce for validation
      try {
        const payloadJson = atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'));
        const payload = JSON.parse(payloadJson) as { nonce?: string };

        // Validate nonce if present in payload
        if (payload.nonce !== undefined && payload.nonce !== expectedNonce) {
          return {
            valid: false,
            error: 'Nonce mismatch',
          };
        }
      } catch {
        // Payload parsing failed - continue with basic validation
      }

      // Note: Full cryptographic verification is not yet implemented.
      // This basic implementation should only be used for development/testing.

      return {
        valid: true,
        submission: response.presentation_submission,
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Verification failed',
      };
    }
  }

  /**
   * Generate a cryptographically random nonce
   */
  private generateNonce(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
