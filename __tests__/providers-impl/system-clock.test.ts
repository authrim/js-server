import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { systemClock, mockClock } from '../../src/providers-impl/system-clock.js';

describe('systemClock', () => {
  describe('nowSeconds', () => {
    it('should return current time in seconds', () => {
      const clock = systemClock();
      const now = Math.floor(Date.now() / 1000);
      const result = clock.nowSeconds();

      // Allow 1 second tolerance
      expect(result).toBeGreaterThanOrEqual(now - 1);
      expect(result).toBeLessThanOrEqual(now + 1);
    });

    it('should return integer value', () => {
      const clock = systemClock();
      const result = clock.nowSeconds();
      expect(Number.isInteger(result)).toBe(true);
    });
  });

  describe('nowMs', () => {
    it('should return current time in milliseconds', () => {
      const clock = systemClock();
      const now = Date.now();
      const result = clock.nowMs();

      // Allow 100ms tolerance
      expect(result).toBeGreaterThanOrEqual(now - 100);
      expect(result).toBeLessThanOrEqual(now + 100);
    });

    it('should return value approximately 1000x nowSeconds', () => {
      const clock = systemClock();
      const seconds = clock.nowSeconds();
      const ms = clock.nowMs();

      expect(Math.floor(ms / 1000)).toBe(seconds);
    });
  });
});

describe('mockClock', () => {
  it('should return initial time', () => {
    const initialTime = 1704067200000; // 2024-01-01T00:00:00Z
    const clock = mockClock(initialTime);

    expect(clock.nowMs()).toBe(initialTime);
    expect(clock.nowSeconds()).toBe(Math.floor(initialTime / 1000));
  });

  it('should advance time', () => {
    const initialTime = 1704067200000;
    const clock = mockClock(initialTime);

    clock.advance(5000); // 5 seconds

    expect(clock.nowMs()).toBe(initialTime + 5000);
    expect(clock.nowSeconds()).toBe(Math.floor((initialTime + 5000) / 1000));
  });

  it('should set time', () => {
    const clock = mockClock(1000);

    clock.setTime(2000);

    expect(clock.nowMs()).toBe(2000);
  });

  it('should allow negative advance (go back in time)', () => {
    const initialTime = 1704067200000;
    const clock = mockClock(initialTime);

    clock.advance(-1000);

    expect(clock.nowMs()).toBe(initialTime - 1000);
  });
});
