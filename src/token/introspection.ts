/**
 * Token Introspection (RFC 7662)
 *
 * OAuth 2.0 Token Introspection
 */

import type { HttpProvider } from '../providers/http.js';
import type { IntrospectionRequest, IntrospectionResponse } from '../types/token.js';
import { AuthrimServerError } from '../types/errors.js';
import { encodeBasicCredentials } from '../utils/auth.js';

/**
 * Introspection client configuration
 */
export interface IntrospectionClientConfig {
  /** Introspection endpoint URL */
  endpoint: string;
  /** Client ID */
  clientId: string;
  /** Client secret */
  clientSecret: string;
  /** HTTP provider */
  http: HttpProvider;
}

/**
 * Token Introspection Client
 *
 * Calls the authorization server's introspection endpoint to check token validity.
 */
export class IntrospectionClient {
  private readonly config: IntrospectionClientConfig;

  constructor(config: IntrospectionClientConfig) {
    this.config = config;
  }

  /**
   * Introspect a token
   *
   * @param request - Introspection request
   * @returns Introspection response
   */
  async introspect(request: IntrospectionRequest): Promise<IntrospectionResponse> {
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
          'Accept': 'application/json',
        },
        body: body.toString(),
      });

      if (!response.ok) {
        // Consume response body to release the connection
        await response.text().catch(() => {});
        throw new AuthrimServerError(
          'introspection_error',
          `Introspection request failed: ${response.status} ${response.statusText}`
        );
      }

      const result = await response.json() as IntrospectionResponse;
      return result;
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }

      throw new AuthrimServerError(
        'introspection_error',
        `Introspection request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }
}
