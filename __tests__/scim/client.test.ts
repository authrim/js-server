import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScimClient } from '../../src/scim/client.js';
import type { HttpProvider } from '../../src/providers/http.js';

describe('ScimClient', () => {
  let mockHttp: HttpProvider;
  let client: ScimClient;

  beforeEach(() => {
    mockHttp = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: {
          get: vi.fn().mockReturnValue(null),
        },
        json: vi.fn().mockResolvedValue({}),
      }),
    };

    client = new ScimClient({
      baseUrl: 'https://scim.example.com',
      http: mockHttp,
      accessToken: 'test-token',
    });
  });

  describe('Users', () => {
    describe('createUser()', () => {
      it('should create a user', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 201,
          json: vi.fn().mockResolvedValue({
            id: 'user-123',
            userName: 'john.doe',
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          }),
        });

        const result = await client.createUser({
          userName: 'john.doe',
          name: { givenName: 'John', familyName: 'Doe' },
        });

        expect(result.id).toBe('user-123');
        expect(result.userName).toBe('john.doe');
        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Users',
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Content-Type': 'application/scim+json',
              'Accept': 'application/scim+json',
              'Authorization': 'Bearer test-token',
            }),
          })
        );
      });
    });

    describe('getUser()', () => {
      it('should get a user by ID', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            id: 'user-123',
            userName: 'john.doe',
          }),
        });

        const result = await client.getUser('user-123');

        expect(result.id).toBe('user-123');
        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Users/user-123',
          expect.any(Object)
        );
      });

      it('should URL-encode user ID', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ id: 'user/with/slashes' }),
        });

        await client.getUser('user/with/slashes');

        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Users/user%2Fwith%2Fslashes',
          expect.any(Object)
        );
      });
    });

    describe('getUserConditional()', () => {
      it('should send If-None-Match header when provided', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          headers: {
            get: vi.fn().mockReturnValue('"etag-123"'),
          },
          json: vi.fn().mockResolvedValue({ id: 'user-123' }),
        });

        const result = await client.getUserConditional('user-123', {
          ifNoneMatch: '"etag-previous"',
        });

        expect(result.notModified).toBe(false);
        expect(result.resource?.id).toBe('user-123');
        expect(result.etag).toBe('"etag-123"');

        const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(call[1].headers['If-None-Match']).toBe('"etag-previous"');
      });

      it('should return notModified: true on 304 response', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 304,
          headers: {
            get: vi.fn().mockReturnValue('"etag-123"'),
          },
        });

        const result = await client.getUserConditional('user-123', {
          ifNoneMatch: '"etag-123"',
        });

        expect(result.notModified).toBe(true);
        expect(result.resource).toBeUndefined();
      });
    });

    describe('listUsers()', () => {
      it('should list users', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            totalResults: 2,
            itemsPerPage: 2,
            startIndex: 1,
            Resources: [
              { id: 'user-1', userName: 'user1' },
              { id: 'user-2', userName: 'user2' },
            ],
          }),
        });

        const result = await client.listUsers();

        expect(result.totalResults).toBe(2);
        expect(result.Resources).toHaveLength(2);
      });

      it('should apply filter options', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            totalResults: 1,
            Resources: [{ id: 'user-1' }],
          }),
        });

        await client.listUsers({
          filter: 'userName eq "john"',
          sortBy: 'userName',
          sortOrder: 'ascending',
          startIndex: 1,
          count: 10,
        });

        const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
        const url = new URL(call[0]);
        expect(url.searchParams.get('filter')).toBe('userName eq "john"');
        expect(url.searchParams.get('sortBy')).toBe('userName');
        expect(url.searchParams.get('sortOrder')).toBe('ascending');
        expect(url.searchParams.get('startIndex')).toBe('1');
        expect(url.searchParams.get('count')).toBe('10');
      });

      it('should apply attributes filter', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ Resources: [] }),
        });

        await client.listUsers({
          attributes: ['userName', 'name.givenName'],
          excludedAttributes: ['emails'],
        });

        const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
        const url = new URL(call[0]);
        expect(url.searchParams.get('attributes')).toBe('userName,name.givenName');
        expect(url.searchParams.get('excludedAttributes')).toBe('emails');
      });
    });

    describe('updateUser()', () => {
      it('should update a user', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            id: 'user-123',
            userName: 'john.doe.updated',
          }),
        });

        const result = await client.updateUser('user-123', {
          userName: 'john.doe.updated',
        });

        expect(result.userName).toBe('john.doe.updated');
        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Users/user-123',
          expect.objectContaining({
            method: 'PUT',
          })
        );
      });

      it('should send If-Match header for optimistic locking', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ id: 'user-123' }),
        });

        await client.updateUser(
          'user-123',
          { userName: 'updated' },
          { ifMatch: '"etag-123"' }
        );

        const call = (mockHttp.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(call[1].headers['If-Match']).toBe('"etag-123"');
      });
    });

    describe('patchUser()', () => {
      it('should patch a user', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ id: 'user-123', active: false }),
        });

        const result = await client.patchUser('user-123', {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [
            { op: 'replace', path: 'active', value: false },
          ],
        });

        expect(result.active).toBe(false);
        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Users/user-123',
          expect.objectContaining({
            method: 'PATCH',
          })
        );
      });
    });

    describe('deleteUser()', () => {
      it('should delete a user', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 204,
        });

        await expect(client.deleteUser('user-123')).resolves.toBeUndefined();

        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Users/user-123',
          expect.objectContaining({
            method: 'DELETE',
          })
        );
      });
    });
  });

  describe('Groups', () => {
    describe('createGroup()', () => {
      it('should create a group', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 201,
          json: vi.fn().mockResolvedValue({
            id: 'group-123',
            displayName: 'Admins',
          }),
        });

        const result = await client.createGroup({
          displayName: 'Admins',
        });

        expect(result.id).toBe('group-123');
        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Groups',
          expect.objectContaining({ method: 'POST' })
        );
      });
    });

    describe('getGroup()', () => {
      it('should get a group by ID', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            id: 'group-123',
            displayName: 'Admins',
          }),
        });

        const result = await client.getGroup('group-123');

        expect(result.displayName).toBe('Admins');
      });
    });

    describe('getGroupConditional()', () => {
      it('should return notModified: true on 304 response', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 304,
          headers: {
            get: vi.fn().mockReturnValue('"etag-123"'),
          },
        });

        const result = await client.getGroupConditional('group-123', {
          ifNoneMatch: '"etag-123"',
        });

        expect(result.notModified).toBe(true);
      });
    });

    describe('listGroups()', () => {
      it('should list groups', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            totalResults: 2,
            Resources: [
              { id: 'group-1', displayName: 'Admins' },
              { id: 'group-2', displayName: 'Users' },
            ],
          }),
        });

        const result = await client.listGroups();

        expect(result.totalResults).toBe(2);
      });
    });

    describe('updateGroup()', () => {
      it('should update a group', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            id: 'group-123',
            displayName: 'Super Admins',
          }),
        });

        const result = await client.updateGroup('group-123', {
          displayName: 'Super Admins',
        });

        expect(result.displayName).toBe('Super Admins');
        expect(mockHttp.fetch).toHaveBeenCalledWith(
          'https://scim.example.com/Groups/group-123',
          expect.objectContaining({ method: 'PUT' })
        );
      });
    });

    describe('patchGroup()', () => {
      it('should patch a group', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({
            id: 'group-123',
            members: [{ value: 'user-1' }],
          }),
        });

        const result = await client.patchGroup('group-123', {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [
            { op: 'add', path: 'members', value: [{ value: 'user-1' }] },
          ],
        });

        expect(result.members).toHaveLength(1);
      });
    });

    describe('deleteGroup()', () => {
      it('should delete a group', async () => {
        mockHttp.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 204,
        });

        await expect(client.deleteGroup('group-123')).resolves.toBeUndefined();
      });
    });
  });

  describe('Error Handling', () => {
    it('should throw on HTTP error', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: vi.fn().mockResolvedValue({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
          detail: 'User not found',
          status: '404',
        }),
      });

      await expect(client.getUser('nonexistent'))
        .rejects.toThrow('SCIM request failed: 404 Not Found');
    });

    it('should throw on network error', async () => {
      mockHttp.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

      await expect(client.getUser('user-123'))
        .rejects.toThrow('SCIM request failed: Network failure');
    });

    it('should throw on JSON parse error', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: vi.fn().mockRejectedValue(new Error('Invalid JSON')),
        text: vi.fn().mockResolvedValue('Internal error'),
      });

      await expect(client.getUser('user-123'))
        .rejects.toThrow('SCIM request failed: 500 Internal Server Error');
    });

    it('should throw on 412 Precondition Failed (optimistic locking)', async () => {
      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 412,
        statusText: 'Precondition Failed',
        json: vi.fn().mockResolvedValue({}),
      });

      await expect(
        client.updateUser('user-123', { userName: 'test' }, { ifMatch: '"old-etag"' })
      ).rejects.toThrow('SCIM request failed: 412 Precondition Failed');
    });
  });

  describe('Base URL handling', () => {
    it('should handle baseUrl with trailing slash', async () => {
      client = new ScimClient({
        baseUrl: 'https://scim.example.com/',
        http: mockHttp,
        accessToken: 'test-token',
      });

      mockHttp.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({ id: 'user-123' }),
      });

      await client.getUser('user-123');

      expect(mockHttp.fetch).toHaveBeenCalledWith(
        'https://scim.example.com/Users/user-123',
        expect.any(Object)
      );
    });
  });
});
