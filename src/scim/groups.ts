/**
 * SCIM Group Helpers
 */

import type { ScimGroup, ScimGroupMember, ScimPatchRequest, ScimPatchOperation } from './types.js';

/**
 * Build a SCIM group object
 */
export function buildScimGroup(
  displayName: string,
  members?: ScimGroupMember[]
): Omit<ScimGroup, 'id' | 'meta'> {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName,
    members,
  };
}

/**
 * Build a patch request to add members to a group
 */
export function addMembersPatch(memberIds: string[]): ScimPatchRequest {
  const operations: ScimPatchOperation[] = memberIds.map((id) => ({
    op: 'add',
    path: 'members',
    value: [{ value: id }],
  }));

  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: operations,
  };
}

/**
 * Build a patch request to remove members from a group
 */
export function removeMembersPatch(memberIds: string[]): ScimPatchRequest {
  const operations: ScimPatchOperation[] = memberIds.map((id) => ({
    op: 'remove',
    path: `members[value eq "${id}"]`,
  }));

  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: operations,
  };
}

/**
 * Check if a group contains a member
 */
export function hasMember(group: ScimGroup, memberId: string): boolean {
  return group.members?.some((m) => m.value === memberId) ?? false;
}
