/**
 * System Clock Provider Implementation
 *
 * Uses Date.now() for time operations.
 */

import type { ClockProvider } from '../providers/clock.js';

/**
 * Create a system clock provider
 *
 * Uses Date.now() which is available in all JavaScript runtimes.
 *
 * @returns ClockProvider implementation
 */
export function systemClock(): ClockProvider {
  return {
    nowSeconds(): number {
      return Math.floor(Date.now() / 1000);
    },

    nowMs(): number {
      return Date.now();
    },
  };
}

/**
 * Create a mock clock provider for testing
 *
 * @param initialTime - Initial time in milliseconds
 * @returns ClockProvider with time control methods
 */
export function mockClock(
  initialTime: number = Date.now()
): ClockProvider & { advance(ms: number): void; setTime(ms: number): void } {
  let currentTime = initialTime;

  return {
    nowSeconds(): number {
      return Math.floor(currentTime / 1000);
    },

    nowMs(): number {
      return currentTime;
    },

    advance(ms: number): void {
      currentTime += ms;
    },

    setTime(ms: number): void {
      currentTime = ms;
    },
  };
}
