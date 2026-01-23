/**
 * SCIM 2.0 Client
 *
 * System for Cross-domain Identity Management (RFC 7643, RFC 7644)
 */

import type { HttpProvider } from '../providers/http.js';
import type {
  ScimUser,
  ScimGroup,
  ScimListResponse,
  ScimFilterOptions,
  ScimPatchRequest,
  ScimUpdateOptions,
  ScimGetOptions,
  ScimConditionalGetResult,
} from './types.js';
import { AuthrimServerError } from '../types/errors.js';

/**
 * SCIM Client configuration
 */
export interface ScimClientConfig {
  /** SCIM service provider URL */
  baseUrl: string;
  /** HTTP provider */
  http: HttpProvider;
  /** Access token for authentication */
  accessToken: string;
}

/**
 * SCIM 2.0 Client
 *
 * Provides CRUD operations for Users and Groups.
 */
export class ScimClient {
  private readonly config: ScimClientConfig;

  constructor(config: ScimClientConfig) {
    this.config = config;
  }

  // ==================== Users ====================

  /**
   * Create a user
   */
  async createUser(user: Omit<ScimUser, 'id' | 'meta'>): Promise<ScimUser> {
    return this.request<ScimUser>('/Users', {
      method: 'POST',
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        ...user,
      }),
    });
  }

  /**
   * Get a user by ID
   *
   * For conditional requests with If-None-Match support, use `getUserConditional()` instead.
   */
  async getUser(id: string): Promise<ScimUser> {
    return this.request<ScimUser>(`/Users/${encodeURIComponent(id)}`);
  }

  /**
   * Get a user by ID with conditional request support
   *
   * Use this method when you want to check if a resource has changed using ETags.
   * Returns 304 Not Modified if the ETag matches, avoiding unnecessary data transfer.
   *
   * @param id - User ID
   * @param options - Get options including If-None-Match
   * @returns Conditional result with resource, etag, and notModified flag
   */
  async getUserConditional(id: string, options?: ScimGetOptions): Promise<ScimConditionalGetResult<ScimUser>> {
    return this.conditionalRequest<ScimUser>(`/Users/${encodeURIComponent(id)}`, options);
  }

  /**
   * List users
   */
  async listUsers(options?: ScimFilterOptions): Promise<ScimListResponse<ScimUser>> {
    const params = this.buildFilterParams(options);
    const query = params.toString();
    return this.request<ScimListResponse<ScimUser>>(`/Users${query ? `?${query}` : ''}`);
  }

  /**
   * Update a user (replace)
   *
   * @param id - User ID
   * @param user - User data to update
   * @param options - Update options including If-Match for optimistic locking
   */
  async updateUser(id: string, user: Partial<ScimUser>, options?: ScimUpdateOptions): Promise<ScimUser> {
    const body = Object.assign(
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'] },
      user
    );
    const headers: Record<string, string> = {};
    if (options?.ifMatch) {
      headers['If-Match'] = options.ifMatch;
    }
    return this.request<ScimUser>(`/Users/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
      headers,
    });
  }

  /**
   * Patch a user
   *
   * @param id - User ID
   * @param patch - Patch operations
   * @param options - Update options including If-Match for optimistic locking
   */
  async patchUser(id: string, patch: ScimPatchRequest, options?: ScimUpdateOptions): Promise<ScimUser> {
    const headers: Record<string, string> = {};
    if (options?.ifMatch) {
      headers['If-Match'] = options.ifMatch;
    }
    return this.request<ScimUser>(`/Users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
      headers,
    });
  }

  /**
   * Delete a user
   */
  async deleteUser(id: string): Promise<void> {
    await this.request<void>(`/Users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // ==================== Groups ====================

  /**
   * Create a group
   */
  async createGroup(group: Omit<ScimGroup, 'id' | 'meta'>): Promise<ScimGroup> {
    const body = Object.assign(
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'] },
      group
    );
    return this.request<ScimGroup>('/Groups', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /**
   * Get a group by ID
   *
   * For conditional requests with If-None-Match support, use `getGroupConditional()` instead.
   */
  async getGroup(id: string): Promise<ScimGroup> {
    return this.request<ScimGroup>(`/Groups/${encodeURIComponent(id)}`);
  }

  /**
   * Get a group by ID with conditional request support
   *
   * Use this method when you want to check if a resource has changed using ETags.
   * Returns 304 Not Modified if the ETag matches, avoiding unnecessary data transfer.
   *
   * @param id - Group ID
   * @param options - Get options including If-None-Match
   * @returns Conditional result with resource, etag, and notModified flag
   */
  async getGroupConditional(id: string, options?: ScimGetOptions): Promise<ScimConditionalGetResult<ScimGroup>> {
    return this.conditionalRequest<ScimGroup>(`/Groups/${encodeURIComponent(id)}`, options);
  }

  /**
   * List groups
   */
  async listGroups(options?: ScimFilterOptions): Promise<ScimListResponse<ScimGroup>> {
    const params = this.buildFilterParams(options);
    const query = params.toString();
    return this.request<ScimListResponse<ScimGroup>>(`/Groups${query ? `?${query}` : ''}`);
  }

  /**
   * Update a group (replace)
   *
   * @param id - Group ID
   * @param group - Group data to update
   * @param options - Update options including If-Match for optimistic locking
   */
  async updateGroup(id: string, group: Partial<ScimGroup>, options?: ScimUpdateOptions): Promise<ScimGroup> {
    const headers: Record<string, string> = {};
    if (options?.ifMatch) {
      headers['If-Match'] = options.ifMatch;
    }
    return this.request<ScimGroup>(`/Groups/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        ...group,
      }),
      headers,
    });
  }

  /**
   * Patch a group
   *
   * @param id - Group ID
   * @param patch - Patch operations
   * @param options - Update options including If-Match for optimistic locking
   */
  async patchGroup(id: string, patch: ScimPatchRequest, options?: ScimUpdateOptions): Promise<ScimGroup> {
    const headers: Record<string, string> = {};
    if (options?.ifMatch) {
      headers['If-Match'] = options.ifMatch;
    }
    return this.request<ScimGroup>(`/Groups/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
      headers,
    });
  }

  /**
   * Delete a group
   */
  async deleteGroup(id: string): Promise<void> {
    await this.request<void>(`/Groups/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // ==================== Helpers ====================

  /**
   * Make a conditional request that handles 304 Not Modified
   */
  private async conditionalRequest<T>(
    path: string,
    options?: ScimGetOptions
  ): Promise<ScimConditionalGetResult<T>> {
    const url = `${this.config.baseUrl.replace(/\/$/, '')}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/scim+json',
      'Accept': 'application/scim+json',
      'Authorization': `Bearer ${this.config.accessToken}`,
    };

    if (options?.ifNoneMatch) {
      headers['If-None-Match'] = options.ifNoneMatch;
    }

    try {
      const response = await this.config.http.fetch(url, { headers });

      // Handle 304 Not Modified
      if (response.status === 304) {
        return {
          notModified: true,
          etag: response.headers.get('ETag') ?? undefined,
        };
      }

      if (!response.ok) {
        // Try to get error details from response body, or consume it to release connection
        const error = await response.json().catch(async () => {
          await response.text().catch(() => {});
          return {};
        });
        throw new AuthrimServerError(
          'network_error',
          `SCIM request failed: ${response.status} ${response.statusText}`,
          { details: error as Record<string, unknown> }
        );
      }

      const resource = await response.json() as T;
      return {
        resource,
        etag: response.headers.get('ETag') ?? undefined,
        notModified: false,
      };
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }
      throw new AuthrimServerError(
        'network_error',
        `SCIM request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  private buildFilterParams(options?: ScimFilterOptions): URLSearchParams {
    const params = new URLSearchParams();

    if (options?.filter) {
      params.set('filter', options.filter);
    }
    if (options?.sortBy) {
      params.set('sortBy', options.sortBy);
    }
    if (options?.sortOrder) {
      params.set('sortOrder', options.sortOrder);
    }
    if (options?.startIndex !== undefined) {
      params.set('startIndex', options.startIndex.toString());
    }
    if (options?.count !== undefined) {
      params.set('count', options.count.toString());
    }
    if (options?.attributes?.length) {
      params.set('attributes', options.attributes.join(','));
    }
    if (options?.excludedAttributes?.length) {
      params.set('excludedAttributes', options.excludedAttributes.join(','));
    }

    return params;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const url = `${this.config.baseUrl.replace(/\/$/, '')}${path}`;

    try {
      const response = await this.config.http.fetch(url, {
        ...init,
        headers: {
          'Content-Type': 'application/scim+json',
          'Accept': 'application/scim+json',
          'Authorization': `Bearer ${this.config.accessToken}`,
          ...(init?.headers ?? {}),
        },
      });

      if (response.status === 204) {
        return undefined as T;
      }

      if (!response.ok) {
        // Try to get error details from response body, or consume it to release connection
        const error = await response.json().catch(async () => {
          await response.text().catch(() => {});
          return {};
        });
        throw new AuthrimServerError(
          'network_error',
          `SCIM request failed: ${response.status} ${response.statusText}`,
          { details: error as Record<string, unknown> }
        );
      }

      return response.json() as Promise<T>;
    } catch (error) {
      if (error instanceof AuthrimServerError) {
        throw error;
      }
      throw new AuthrimServerError(
        'network_error',
        `SCIM request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }
}
