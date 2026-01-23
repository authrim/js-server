/**
 * Token Revocation (RFC 7009)
 *
 * OAuth 2.0 Token Revocation
 */

import type { HttpProvider } from '../providers/http.js';
import type { RevocationRequest } from '../types/token.js';
import { AuthrimServerError } from '../types/errors.js';
import { encodeBasicCredentials } from '../utils/auth.js';

/**
 * Revocation client configuration
 */
export interface RevocationClientConfig {
  /** Revocation endpoint URL */
  endpoint: string;
  /** Client ID */
  clientId: string;
  /** Client secret */
  clientSecret: string;
  /** HTTP provider */
  http: HttpProvider;
}

/**
 * Token Revocation Client
 *
 * Calls the authorization server's revocation endpoint to invalidate tokens.
 */
export class RevocationClient {
  private readonly config: RevocationClientConfig;

  constructor(config: RevocationClientConfig) {
    this.config = config;
  }

  /**
   * Revoke a token
   *
   * Note: Per RFC 7009, a successful response (200) does not guarantee
   * the token was revoked. The server may silently ignore invalid tokens.
   *
   * @param request - Revocation request
   */
  async revoke(request: RevocationRequest): Promise<void> {
    const body = new URLSearchParams();
    body.set('token', request.token);

    if (request.token_type_hint) {
      body.set('token_type_hint', request.token_type_hint);
    }

    // Build Basic auth header with proper encoding per RFC 7617
    const credentials = encodeBasicCredentials(this.config.clientId, this.config.clientSecret);

    try {
      const response = await this.config.http.fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${credentials}`,
        },
        body: body.toString(),
      });

      // Per RFC 7009, 200 is success even if token was already revoked or invalid
      if (!response.ok) {
        // Consume response body to release the connection
        await response.text().catch(() => {});
        throw new AuthrimServerError(
          'revocation_error',
          `Revocation request failed: ${response.status} ${response.statusText}`
        );
      }
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }

      throw new AuthrimServerError(
        'revocation_error',
        `Revocation request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }
}
