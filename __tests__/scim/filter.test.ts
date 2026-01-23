import { describe, it, expect } from 'vitest';
import { ScimFilter, scimFilter } from '../../src/scim/filter.js';

describe('ScimFilter', () => {
  describe('basic operations', () => {
    it('should build simple equality filter', () => {
      const filter = new ScimFilter()
        .where('userName', 'eq', 'john@example.com')
        .build();

      expect(filter).toBe('userName eq "john@example.com"');
    });

    it('should build filter with boolean value', () => {
      const filter = new ScimFilter()
        .where('active', 'eq', true)
        .build();

      expect(filter).toBe('active eq true');
    });

    it('should build filter with number value', () => {
      const filter = new ScimFilter()
        .where('meta.version', 'gt', 5)
        .build();

      expect(filter).toBe('meta.version gt 5');
    });

    it('should build presence filter', () => {
      const filter = new ScimFilter()
        .where('emails', 'pr')
        .build();

      expect(filter).toBe('emails pr');
    });
  });

  describe('operators', () => {
    it('should support all comparison operators', () => {
      const operators = ['eq', 'ne', 'co', 'sw', 'ew', 'gt', 'ge', 'lt', 'le'] as const;

      for (const op of operators) {
        const filter = new ScimFilter()
          .where('attr', op, 'value')
          .build();

        expect(filter).toBe(`attr ${op} "value"`);
      }
    });
  });

  describe('logical operators', () => {
    it('should build filter with AND', () => {
      const filter = new ScimFilter()
        .where('userName', 'eq', 'john')
        .and()
        .where('active', 'eq', true)
        .build();

      expect(filter).toBe('userName eq "john" and active eq true');
    });

    it('should build filter with OR', () => {
      const filter = new ScimFilter()
        .where('userName', 'eq', 'john')
        .or()
        .where('userName', 'eq', 'jane')
        .build();

      expect(filter).toBe('userName eq "john" or userName eq "jane"');
    });

    it('should build filter with NOT', () => {
      const filter = new ScimFilter()
        .not()
        .where('active', 'eq', false)
        .build();

      expect(filter).toBe('not active eq false');
    });

    it('should build filter with parentheses', () => {
      const filter = new ScimFilter()
        .openParen()
        .where('userName', 'eq', 'john')
        .or()
        .where('userName', 'eq', 'jane')
        .closeParen()
        .and()
        .where('active', 'eq', true)
        .build();

      expect(filter).toBe('( userName eq "john" or userName eq "jane" ) and active eq true');
    });
  });

  describe('injection prevention', () => {
    describe('attribute name validation', () => {
      it('should reject attribute with special characters', () => {
        expect(() => {
          new ScimFilter().where('user" or "1"="1', 'eq', 'value');
        }).toThrow('Invalid SCIM attribute name');
      });

      it('should reject attribute starting with number', () => {
        expect(() => {
          new ScimFilter().where('123attr', 'eq', 'value');
        }).toThrow('Invalid SCIM attribute name');
      });

      it('should reject attribute with spaces', () => {
        expect(() => {
          new ScimFilter().where('user name', 'eq', 'value');
        }).toThrow('Invalid SCIM attribute name');
      });

      it('should reject attribute with SQL injection attempt', () => {
        expect(() => {
          new ScimFilter().where("userName; DROP TABLE users;--", 'eq', 'value');
        }).toThrow('Invalid SCIM attribute name');
      });

      it('should reject attribute with parentheses', () => {
        expect(() => {
          new ScimFilter().where('userName()', 'eq', 'value');
        }).toThrow('Invalid SCIM attribute name');
      });

      it('should accept valid dotted attribute names', () => {
        const filter = new ScimFilter()
          .where('name.familyName', 'eq', 'Doe')
          .build();

        expect(filter).toBe('name.familyName eq "Doe"');
      });

      it('should accept valid alphanumeric attributes', () => {
        const filter = new ScimFilter()
          .where('userName2', 'eq', 'john')
          .build();

        expect(filter).toBe('userName2 eq "john"');
      });
    });

    describe('value escaping', () => {
      it('should escape double quotes in values', () => {
        const filter = new ScimFilter()
          .where('description', 'eq', 'Say "Hello"')
          .build();

        expect(filter).toBe('description eq "Say \\"Hello\\""');
      });

      it('should escape backslashes in values', () => {
        const filter = new ScimFilter()
          .where('path', 'eq', 'C:\\Users\\John')
          .build();

        expect(filter).toBe('path eq "C:\\\\Users\\\\John"');
      });

      it('should escape both quotes and backslashes', () => {
        const filter = new ScimFilter()
          .where('data', 'eq', 'Say "Hello\\World"')
          .build();

        expect(filter).toBe('data eq "Say \\"Hello\\\\World\\""');
      });

      it('should handle filter injection attempt in value', () => {
        const filter = new ScimFilter()
          .where('userName', 'eq', '" or "1"="1')
          .build();

        // The quotes should be escaped, preventing injection
        expect(filter).toBe('userName eq "\\" or \\"1\\"=\\"1"');
      });
    });

    describe('value type validation', () => {
      it('should reject object values', () => {
        expect(() => {
          new ScimFilter().where('attr', 'eq', { toString: () => 'malicious' } as unknown as string);
        }).toThrow('Invalid SCIM filter value type');
      });

      it('should reject array values', () => {
        expect(() => {
          new ScimFilter().where('attr', 'eq', ['a', 'b'] as unknown as string);
        }).toThrow('Invalid SCIM filter value type');
      });

      it('should reject null values', () => {
        expect(() => {
          new ScimFilter().where('attr', 'eq', null as unknown as string);
        }).toThrow('Invalid SCIM filter value type');
      });

      it('should reject undefined values for non-pr operators', () => {
        // undefined value with non-pr operator should just not add the condition
        const filter = new ScimFilter()
          .where('attr', 'eq', undefined)
          .build();

        expect(filter).toBe('');
      });

      it('should accept string values', () => {
        const filter = new ScimFilter()
          .where('attr', 'eq', 'string')
          .build();

        expect(filter).toBe('attr eq "string"');
      });

      it('should accept number values', () => {
        const filter = new ScimFilter()
          .where('attr', 'gt', 42)
          .build();

        expect(filter).toBe('attr gt 42');
      });

      it('should accept boolean values', () => {
        const filter = new ScimFilter()
          .where('attr', 'eq', false)
          .build();

        expect(filter).toBe('attr eq false');
      });
    });
  });

  describe('utility methods', () => {
    it('should reset filter', () => {
      const filter = new ScimFilter()
        .where('userName', 'eq', 'john')
        .reset()
        .where('active', 'eq', true)
        .build();

      expect(filter).toBe('active eq true');
    });

    it('should create filter via factory function', () => {
      const filter = scimFilter()
        .where('userName', 'eq', 'john')
        .build();

      expect(filter).toBe('userName eq "john"');
    });
  });

  describe('complex filters', () => {
    it('should build complex nested filter', () => {
      const filter = new ScimFilter()
        .where('schemas', 'eq', 'urn:ietf:params:scim:schemas:core:2.0:User')
        .and()
        .openParen()
        .where('userName', 'sw', 'john')
        .or()
        .where('emails.value', 'co', '@example.com')
        .closeParen()
        .and()
        .where('active', 'eq', true)
        .build();

      expect(filter).toBe(
        'schemas eq "urn:ietf:params:scim:schemas:core:2.0:User" and ' +
        '( userName sw "john" or emails.value co "@example.com" ) and ' +
        'active eq true'
      );
    });
  });
});
