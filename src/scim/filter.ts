/**
 * SCIM Filter Builder
 *
 * Helper for building SCIM filter expressions (RFC 7644 Section 3.4.2.2)
 */

/**
 * SCIM filter operators
 */
type ScimFilterOperator = 'eq' | 'ne' | 'co' | 'sw' | 'ew' | 'gt' | 'ge' | 'lt' | 'le' | 'pr';

/**
 * Valid attribute name pattern (RFC 7644)
 * Attribute names can be alphanumeric with dots for sub-attributes
 */
const VALID_ATTRIBUTE_PATTERN = /^[a-zA-Z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)*$/;

/**
 * Escape a string value for SCIM filter
 *
 * Per RFC 7644 Section 3.4.2.2, string values in filters must be enclosed
 * in double quotes and special characters must be escaped.
 */
function escapeFilterValue(value: string): string {
  // Escape backslash first, then double quotes
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"');
}

/**
 * Validate attribute name to prevent injection
 */
function validateAttributeName(attribute: string): void {
  if (!VALID_ATTRIBUTE_PATTERN.test(attribute)) {
    throw new Error(`Invalid SCIM attribute name: ${attribute}`);
  }
}

/**
 * SCIM Filter Builder
 *
 * Provides a fluent API for building SCIM filter expressions.
 * All values are properly escaped to prevent filter injection attacks.
 *
 * @example
 * ```typescript
 * const filter = new ScimFilter()
 *   .where('userName', 'eq', 'john@example.com')
 *   .and()
 *   .where('active', 'eq', true)
 *   .build();
 * // Result: 'userName eq "john@example.com" and active eq true'
 * ```
 */
export class ScimFilter {
  private parts: string[] = [];

  /**
   * Add a filter condition
   *
   * @param attribute - Attribute name (validated against injection)
   * @param operator - Filter operator
   * @param value - Value to compare (strings are escaped)
   * @throws Error if attribute name is invalid or value type is invalid
   */
  where(attribute: string, operator: ScimFilterOperator, value?: string | number | boolean): this {
    // Validate attribute name to prevent injection
    validateAttributeName(attribute);

    if (operator === 'pr') {
      this.parts.push(`${attribute} pr`);
    } else if (value !== undefined) {
      // Runtime type check to prevent injection via custom toString()
      // This guards against objects with malicious toString() implementations
      const valueType = typeof value;
      if (valueType !== 'string' && valueType !== 'number' && valueType !== 'boolean') {
        throw new Error(`Invalid SCIM filter value type: ${valueType}`);
      }

      // Properly escape string values to prevent injection
      const formattedValue = valueType === 'string'
        ? `"${escapeFilterValue(value as string)}"`
        : String(value);
      this.parts.push(`${attribute} ${operator} ${formattedValue}`);
    }
    return this;
  }

  /**
   * Add AND logical operator
   */
  and(): this {
    this.parts.push('and');
    return this;
  }

  /**
   * Add OR logical operator
   */
  or(): this {
    this.parts.push('or');
    return this;
  }

  /**
   * Add NOT logical operator
   */
  not(): this {
    this.parts.push('not');
    return this;
  }

  /**
   * Add opening parenthesis
   */
  openParen(): this {
    this.parts.push('(');
    return this;
  }

  /**
   * Add closing parenthesis
   */
  closeParen(): this {
    this.parts.push(')');
    return this;
  }

  /**
   * Build the filter string
   */
  build(): string {
    return this.parts.join(' ');
  }

  /**
   * Reset the filter
   */
  reset(): this {
    this.parts = [];
    return this;
  }
}

/**
 * Create a new SCIM filter
 */
export function scimFilter(): ScimFilter {
  return new ScimFilter();
}
