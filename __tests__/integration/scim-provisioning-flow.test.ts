/**
 * Integration Test: SCIM Provisioning Flow
 *
 * Tests complete SCIM 2.0 user and group lifecycle:
 * - User creation, retrieval, update, deletion
 * - Group management with members
 * - Filtering, pagination, sorting
 * - Optimistic locking with ETags
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScimClient } from '../../src/scim/client.js';
import type { HttpProvider } from '../../src/providers/http.js';

describe('Integration: SCIM Provisioning Flow', () => {
  let mockHttp: HttpProvider;
  let client: ScimClient;

  // Simulated database for stateful tests
  let usersDb: Map<string, unknown>;
  let groupsDb: Map<string, unknown>;
  let etagCounter: number;

  beforeEach(() => {
    usersDb = new Map();
    groupsDb = new Map();
    etagCounter = 1;

    // Create a more realistic mock that simulates SCIM server behavior
    mockHttp = {
      fetch: vi.fn(),
    };

    client = new ScimClient({
      baseUrl: 'https://scim.example.com/v2',
      http: mockHttp,
      accessToken: 'admin-token',
    });
  });

  describe('Scenario 1: User Lifecycle', () => {
    it('should complete full user lifecycle: create → read → update → delete', async () => {
      const userId = 'user-001';
      let currentEtag = `"etag-${etagCounter++}"`;

      // Step 1: Create user
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: { get: (name: string) => name === 'ETag' ? currentEtag : null },
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          id: userId,
          userName: 'john.doe@example.com',
          name: { givenName: 'John', familyName: 'Doe' },
          active: true,
          meta: {
            resourceType: 'User',
            created: '2024-01-01T00:00:00Z',
            lastModified: '2024-01-01T00:00:00Z',
            version: currentEtag,
          },
        }),
      });

      const createdUser = await client.createUser({
        userName: 'john.doe@example.com',
        name: { givenName: 'John', familyName: 'Doe' },
        active: true,
      });

      expect(createdUser.id).toBe(userId);
      expect(createdUser.userName).toBe('john.doe@example.com');

      // Step 2: Read user
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: (name: string) => name === 'ETag' ? currentEtag : null },
        json: vi.fn().mockResolvedValue({
          ...createdUser,
        }),
      });

      const fetchedUser = await client.getUser(userId);
      expect(fetchedUser.userName).toBe('john.doe@example.com');

      // Step 3: Update user
      currentEtag = `"etag-${etagCounter++}"`;
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: (name: string) => name === 'ETag' ? currentEtag : null },
        json: vi.fn().mockResolvedValue({
          ...createdUser,
          name: { givenName: 'John', familyName: 'Smith' },
          meta: {
            ...createdUser.meta,
            lastModified: '2024-01-02T00:00:00Z',
            version: currentEtag,
          },
        }),
      });

      const updatedUser = await client.updateUser(userId, {
        name: { givenName: 'John', familyName: 'Smith' },
      });

      expect(updatedUser.name?.familyName).toBe('Smith');

      // Step 4: Delete user
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      await expect(client.deleteUser(userId)).resolves.toBeUndefined();
    });
  });

  describe('Scenario 2: Group Management with Members', () => {
    it('should manage group membership lifecycle', async () => {
      const groupId = 'group-001';
      const user1Id = 'user-001';
      const user2Id = 'user-002';

      // Step 1: Create group
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
          id: groupId,
          displayName: 'Engineering Team',
          members: [],
        }),
      });

      const group = await client.createGroup({
        displayName: 'Engineering Team',
      });

      expect(group.id).toBe(groupId);
      expect(group.members).toHaveLength(0);

      // Step 2: Add members via PATCH
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          ...group,
          members: [
            { value: user1Id, display: 'User 1' },
            { value: user2Id, display: 'User 2' },
          ],
        }),
      });

      const groupWithMembers = await client.patchGroup(groupId, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'add',
            path: 'members',
            value: [
              { value: user1Id },
              { value: user2Id },
            ],
          },
        ],
      });

      expect(groupWithMembers.members).toHaveLength(2);

      // Step 3: Remove a member
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          ...group,
          members: [
            { value: user2Id, display: 'User 2' },
          ],
        }),
      });

      const groupAfterRemoval = await client.patchGroup(groupId, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'remove',
            path: `members[value eq "${user1Id}"]`,
          },
        ],
      });

      expect(groupAfterRemoval.members).toHaveLength(1);
      expect(groupAfterRemoval.members?.[0].value).toBe(user2Id);
    });
  });

  describe('Scenario 3: Filtering and Pagination', () => {
    it('should filter users by attribute', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
          totalResults: 2,
          itemsPerPage: 2,
          startIndex: 1,
          Resources: [
            { id: 'user-001', userName: 'active.user1@example.com', active: true },
            { id: 'user-002', userName: 'active.user2@example.com', active: true },
          ],
        }),
      });

      const result = await client.listUsers({
        filter: 'active eq true',
      });

      expect(result.totalResults).toBe(2);
      expect(result.Resources.every(u => u.active)).toBe(true);

      // Verify filter was sent (URLSearchParams uses + for spaces)
      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toContain('filter=active+eq+true');
    });

    it('should paginate through large result sets', async () => {
      // First page
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          totalResults: 100,
          itemsPerPage: 25,
          startIndex: 1,
          Resources: Array.from({ length: 25 }, (_, i) => ({
            id: `user-${i + 1}`,
            userName: `user${i + 1}@example.com`,
          })),
        }),
      });

      const page1 = await client.listUsers({
        startIndex: 1,
        count: 25,
      });

      expect(page1.totalResults).toBe(100);
      expect(page1.Resources).toHaveLength(25);
      expect(page1.startIndex).toBe(1);

      // Second page
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          totalResults: 100,
          itemsPerPage: 25,
          startIndex: 26,
          Resources: Array.from({ length: 25 }, (_, i) => ({
            id: `user-${i + 26}`,
            userName: `user${i + 26}@example.com`,
          })),
        }),
      });

      const page2 = await client.listUsers({
        startIndex: 26,
        count: 25,
      });

      expect(page2.startIndex).toBe(26);
      expect(page2.Resources[0].id).toBe('user-26');
    });

    it('should sort results by attribute', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          totalResults: 3,
          Resources: [
            { id: 'user-1', userName: 'alice@example.com' },
            { id: 'user-2', userName: 'bob@example.com' },
            { id: 'user-3', userName: 'charlie@example.com' },
          ],
        }),
      });

      await client.listUsers({
        sortBy: 'userName',
        sortOrder: 'ascending',
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toContain('sortBy=userName');
      expect(call[0]).toContain('sortOrder=ascending');
    });
  });

  describe('Scenario 4: Optimistic Locking with ETags', () => {
    it('should handle conditional GET (If-None-Match)', async () => {
      const etag = '"version-123"';

      // First request - returns full resource
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: (name: string) => name === 'ETag' ? etag : null },
        json: vi.fn().mockResolvedValue({
          id: 'user-001',
          userName: 'john@example.com',
        }),
      });

      const result1 = await client.getUserConditional('user-001');
      expect(result1.notModified).toBe(false);
      expect(result1.resource?.userName).toBe('john@example.com');
      expect(result1.etag).toBe(etag);

      // Second request with If-None-Match - returns 304
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 304,
        headers: { get: (name: string) => name === 'ETag' ? etag : null },
      });

      const result2 = await client.getUserConditional('user-001', {
        ifNoneMatch: etag,
      });

      expect(result2.notModified).toBe(true);
      expect(result2.resource).toBeUndefined();
    });

    it('should handle concurrent update conflict (412 Precondition Failed)', async () => {
      // Try to update with outdated ETag
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 412,
        statusText: 'Precondition Failed',
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'Resource has been modified',
          status: '412',
        }),
      });

      await expect(
        client.updateUser(
          'user-001',
          { userName: 'updated@example.com' },
          { ifMatch: '"old-etag"' }
        )
      ).rejects.toThrow('412 Precondition Failed');
    });
  });

  describe('Scenario 5: Attribute Selection', () => {
    it('should request only specific attributes', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          totalResults: 1,
          Resources: [
            {
              id: 'user-001',
              userName: 'john@example.com',
              // Only requested attributes returned
            },
          ],
        }),
      });

      await client.listUsers({
        attributes: ['id', 'userName'],
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toContain('attributes=id%2CuserName');
    });

    it('should exclude specific attributes', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          totalResults: 1,
          Resources: [
            {
              id: 'user-001',
              userName: 'john@example.com',
              name: { givenName: 'John', familyName: 'Doe' },
              // emails excluded
            },
          ],
        }),
      });

      await client.listUsers({
        excludedAttributes: ['emails', 'phoneNumbers'],
      });

      const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toContain('excludedAttributes=emails%2CphoneNumbers');
    });
  });

  describe('Scenario 6: User Deprovisioning', () => {
    it('should deactivate user before deletion (soft delete)', async () => {
      const userId = 'user-to-deprovision';

      // Step 1: Deactivate user
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          id: userId,
          userName: 'leaving@example.com',
          active: false,
        }),
      });

      const deactivatedUser = await client.patchUser(userId, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          { op: 'replace', path: 'active', value: false },
        ],
      });

      expect(deactivatedUser.active).toBe(false);

      // Step 2: Remove from groups (simulated)
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({
          id: 'group-001',
          members: [],
        }),
      });

      await client.patchGroup('group-001', {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          { op: 'remove', path: `members[value eq "${userId}"]` },
        ],
      });

      // Step 3: Hard delete (optional)
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      await client.deleteUser(userId);
    });
  });

  describe('Scenario 7: Error Handling', () => {
    it('should handle user not found', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'User not found',
          status: '404',
        }),
      });

      await expect(client.getUser('nonexistent')).rejects.toThrow('404 Not Found');
    });

    it('should handle invalid filter syntax', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          scimType: 'invalidFilter',
          detail: 'Invalid filter syntax',
          status: '400',
        }),
      });

      await expect(
        client.listUsers({ filter: 'invalid syntax here' })
      ).rejects.toThrow('400 Bad Request');
    });

    it('should handle server error', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: vi.fn().mockRejectedValue(new Error('No JSON')),
        text: vi.fn().mockResolvedValue('Internal error'),
      });

      await expect(client.listUsers()).rejects.toThrow('500 Internal Server Error');
    });
  });

  describe('Scenario 8: Bulk Operations Simulation', () => {
    it('should create multiple users in sequence', async () => {
      const usersToCreate = [
        { userName: 'user1@example.com', name: { givenName: 'User', familyName: 'One' } },
        { userName: 'user2@example.com', name: { givenName: 'User', familyName: 'Two' } },
        { userName: 'user3@example.com', name: { givenName: 'User', familyName: 'Three' } },
      ];

      const createdUsers = [];

      for (let i = 0; i < usersToCreate.length; i++) {
        mockHttp.fetch = vi.fn().mockResolvedValueOnce({
          ok: true,
          status: 201,
          json: vi.fn().mockResolvedValue({
            id: `user-${i + 1}`,
            ...usersToCreate[i],
          }),
        });

        const user = await client.createUser(usersToCreate[i]);
        createdUsers.push(user);
      }

      expect(createdUsers).toHaveLength(3);
      expect(createdUsers.map(u => u.userName)).toEqual([
        'user1@example.com',
        'user2@example.com',
        'user3@example.com',
      ]);
    });
  });
});
