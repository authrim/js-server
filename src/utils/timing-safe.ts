/**
 * Timing-Safe Comparison Utilities
 *
 * Prevents timing attacks when comparing secrets.
 *
 * SECURITY NOTE:
 * These functions protect against timing attacks that could reveal the
 * expected value by measuring comparison time. However, the length of
 * the inputs may still be leaked through timing differences. This is
 * generally acceptable because:
 * 1. Input lengths are often known or easily guessable
 * 2. True constant-time for arbitrary lengths is expensive
 * 3. The main attack vector (early return on mismatch) is prevented
 *
 * For maximum security with unknown-length secrets, consider using
 * fixed-length representations (e.g., hashes) for comparison.
 */

/**
 * Compare two strings in constant time
 *
 * This function compares strings without short-circuiting, preventing
 * timing attacks that could reveal information about the expected value.
 *
 * Note: The function does leak whether the lengths are equal, but the
 * actual comparison is constant-time regardless of where mismatches occur.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal
 */
export function timingSafeEqual(a: string, b: string): boolean {
  // Use crypto.timingSafeEqual if available (Node.js)
  if (typeof globalThis.crypto !== 'undefined' && 'timingSafeEqual' in globalThis.crypto) {
    const encoder = new TextEncoder();
    const bufA = encoder.encode(a);
    const bufB = encoder.encode(b);

    // Different lengths: perform a dummy comparison to maintain similar timing
    // Note: Length difference is still detectable, but comparison time is consistent
    if (bufA.length !== bufB.length) {
      // Compare bufA with itself to maintain constant time behavior
      // This ensures we still perform cryptographic comparison operation
      (globalThis.crypto as { timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean })
        .timingSafeEqual(bufA, bufA);
      return false;
    }

    return (globalThis.crypto as { timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean })
      .timingSafeEqual(bufA, bufB);
  }

  // Fallback: manual constant-time comparison
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);

  // XOR comparison - continue even if lengths differ
  // This ensures all bytes are compared regardless of early mismatches
  const maxLen = Math.max(bufA.length, bufB.length);
  let result = bufA.length === bufB.length ? 0 : 1;

  for (let i = 0; i < maxLen; i++) {
    const byteA = bufA[i] ?? 0;
    const byteB = bufB[i] ?? 0;
    result |= byteA ^ byteB;
  }

  return result === 0;
}

/**
 * Compare two byte arrays in constant time
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns true if arrays are equal
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Use crypto.timingSafeEqual if available (Node.js)
  if (typeof globalThis.crypto !== 'undefined' && 'timingSafeEqual' in globalThis.crypto) {
    if (a.length !== b.length) {
      // Compare with itself to maintain constant time
      (globalThis.crypto as { timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean })
        .timingSafeEqual(a, a);
      return false;
    }

    return (globalThis.crypto as { timingSafeEqual: (a: Uint8Array, b: Uint8Array) => boolean })
      .timingSafeEqual(a, b);
  }

  // Fallback: manual constant-time comparison
  const maxLen = Math.max(a.length, b.length);
  let result = a.length === b.length ? 0 : 1;

  for (let i = 0; i < maxLen; i++) {
    const byteA = a[i] ?? 0;
    const byteB = b[i] ?? 0;
    result |= byteA ^ byteB;
  }

  return result === 0;
}
