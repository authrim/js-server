/**
 * Authentication Utilities
 *
 * Common authentication-related helper functions.
 */

/**
 * Encode client credentials for HTTP Basic authentication
 *
 * Per RFC 7617 Section 2.1:
 * 1. The user-id and password are percent-encoded (RFC 3986)
 * 2. Combined with a single colon (:)
 * 3. Encoded using UTF-8
 * 4. Base64 encoded
 *
 * @param clientId - Client identifier
 * @param clientSecret - Client secret
 * @returns Base64-encoded credentials for Authorization header
 */
export function encodeBasicCredentials(clientId: string, clientSecret: string): string {
  // Step 1: URL encode (percent-encode) the credentials per RFC 7617
  // This handles special characters including colons in the client ID/secret
  const encodedId = encodeURIComponent(clientId);
  const encodedSecret = encodeURIComponent(clientSecret);

  // Step 2: Combine with colon
  const credentials = `${encodedId}:${encodedSecret}`;

  // Step 3 & 4: UTF-8 encode then Base64 encode
  const encoder = new TextEncoder();
  const credentialsBytes = encoder.encode(credentials);

  // Convert Uint8Array to base64
  let binary = '';
  for (const byte of credentialsBytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
