/**
 * SCIM 2.0 Type Definitions (RFC 7643, RFC 7644)
 *
 * System for Cross-domain Identity Management
 */

/**
 * SCIM resource metadata
 */
export interface ScimMeta {
  resourceType: string;
  created?: string;
  lastModified?: string;
  location?: string;
  version?: string;
}

/**
 * SCIM name (multi-valued)
 */
export interface ScimName {
  formatted?: string;
  familyName?: string;
  givenName?: string;
  middleName?: string;
  honorificPrefix?: string;
  honorificSuffix?: string;
}

/**
 * SCIM email
 */
export interface ScimEmail {
  value: string;
  type?: string;
  primary?: boolean;
}

/**
 * SCIM phone number
 */
export interface ScimPhoneNumber {
  value: string;
  type?: string;
}

/**
 * SCIM address
 */
export interface ScimAddress {
  formatted?: string;
  streetAddress?: string;
  locality?: string;
  region?: string;
  postalCode?: string;
  country?: string;
  type?: string;
}

/**
 * SCIM User resource (RFC 7643)
 */
export interface ScimUser {
  schemas: string[];
  id?: string;
  externalId?: string;
  meta?: ScimMeta;
  userName: string;
  name?: ScimName;
  displayName?: string;
  nickName?: string;
  profileUrl?: string;
  title?: string;
  userType?: string;
  preferredLanguage?: string;
  locale?: string;
  timezone?: string;
  active?: boolean;
  emails?: ScimEmail[];
  phoneNumbers?: ScimPhoneNumber[];
  addresses?: ScimAddress[];
  [key: string]: unknown;
}

/**
 * SCIM Group member
 */
export interface ScimGroupMember {
  value: string;
  $ref?: string;
  display?: string;
}

/**
 * SCIM Group resource (RFC 7643)
 */
export interface ScimGroup {
  schemas: string[];
  id?: string;
  externalId?: string;
  meta?: ScimMeta;
  displayName: string;
  members?: ScimGroupMember[];
}

/**
 * SCIM list response
 */
export interface ScimListResponse<T> {
  schemas: string[];
  totalResults: number;
  startIndex?: number;
  itemsPerPage?: number;
  Resources: T[];
}

/**
 * SCIM error response
 */
export interface ScimError {
  schemas: string[];
  status: string;
  scimType?: string;
  detail?: string;
}

/**
 * SCIM filter options
 */
export interface ScimFilterOptions {
  filter?: string;
  sortBy?: string;
  sortOrder?: 'ascending' | 'descending';
  startIndex?: number;
  count?: number;
  attributes?: string[];
  excludedAttributes?: string[];
}

/**
 * Options for SCIM update/patch operations with optimistic locking
 */
export interface ScimUpdateOptions {
  /**
   * ETag value for optimistic locking (If-Match header)
   * If provided and doesn't match, the operation will fail with 412 Precondition Failed
   */
  ifMatch?: string;
}

/**
 * Options for SCIM get operations with conditional requests
 */
export interface ScimGetOptions {
  /**
   * ETag value for conditional request (If-None-Match header)
   * If provided and matches, the server returns 304 Not Modified
   */
  ifNoneMatch?: string;
}

/**
 * Result of a conditional GET that may return 304
 */
export interface ScimConditionalGetResult<T> {
  /** The resource if it was returned, or undefined if 304 */
  resource?: T;
  /** ETag of the resource */
  etag?: string;
  /** Whether the response was 304 Not Modified */
  notModified: boolean;
}

/**
 * SCIM patch operation
 */
export interface ScimPatchOperation {
  op: 'add' | 'remove' | 'replace';
  path?: string;
  value?: unknown;
}

/**
 * SCIM patch request
 */
export interface ScimPatchRequest {
  schemas: string[];
  Operations: ScimPatchOperation[];
}
