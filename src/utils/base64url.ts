/**
 * Base64URL Encoding/Decoding Utilities
 *
 * RFC 4648 Section 5 - Base64 Encoding with URL and Filename Safe Alphabet
 */

/**
 * Encode bytes to base64url string
 *
 * @param data - Bytes to encode
 * @returns Base64url-encoded string (no padding)
 */
export function base64UrlEncode(data: Uint8Array): string {
  // Convert to base64
  let base64: string;
  if (typeof Buffer !== 'undefined') {
    // Node.js
    base64 = Buffer.from(data).toString('base64');
  } else {
    // Browser/Edge runtime
    const binary = Array.from(data)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    base64 = btoa(binary);
  }

  // Convert to base64url (replace + with -, / with _, remove padding)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode base64url string to bytes
 *
 * @param str - Base64url-encoded string
 * @returns Decoded bytes
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Convert from base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const paddingNeeded = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(paddingNeeded);

  // Decode
  if (typeof Buffer !== 'undefined') {
    // Node.js
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    // Browser/Edge runtime
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Encode string to base64url
 *
 * @param str - String to encode (UTF-8)
 * @returns Base64url-encoded string
 */
export function base64UrlEncodeString(str: string): string {
  return base64UrlEncode(new TextEncoder().encode(str));
}

/**
 * Decode base64url to string
 *
 * @param str - Base64url-encoded string
 * @returns Decoded string (UTF-8)
 */
export function base64UrlDecodeString(str: string): string {
  return new TextDecoder().decode(base64UrlDecode(str));
}
