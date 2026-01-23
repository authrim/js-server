/**
 * Clock Provider Interface
 *
 * Abstraction for time operations to enable testing and custom time sources.
 */

/**
 * Clock Provider interface
 *
 * Implementations should:
 * - Return consistent, monotonic time values
 * - Use the system clock in production
 * - Allow time manipulation in tests
 */
export interface ClockProvider {
  /**
   * Get current Unix timestamp in seconds
   *
   * @returns Current time as Unix timestamp (seconds since epoch)
   */
  nowSeconds(): number;

  /**
   * Get current time in milliseconds
   *
   * @returns Current time in milliseconds since epoch
   */
  nowMs(): number;
}
