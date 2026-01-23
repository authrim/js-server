/**
 * SCIM 2.0 Support
 */

export { ScimClient, type ScimClientConfig } from './client.js';
export { ScimFilter, scimFilter } from './filter.js';
export {
  getPrimaryEmail,
  getDisplayName,
  buildScimUser,
} from './users.js';
export {
  buildScimGroup,
  addMembersPatch,
  removeMembersPatch,
  hasMember,
} from './groups.js';
export type {
  ScimUser,
  ScimGroup,
  ScimGroupMember,
  ScimListResponse,
  ScimError,
  ScimFilterOptions,
  ScimPatchOperation,
  ScimPatchRequest,
  ScimMeta,
  ScimName,
  ScimEmail,
  ScimPhoneNumber,
  ScimAddress,
} from './types.js';
