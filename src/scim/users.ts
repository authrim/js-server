/**
 * SCIM User Helpers
 */

import type { ScimUser, ScimName } from './types.js';

/**
 * Get the primary email from a SCIM user
 */
export function getPrimaryEmail(user: ScimUser): string | undefined {
  if (!user.emails?.length) {
    return undefined;
  }

  const primary = user.emails.find((e) => e.primary);
  return primary?.value ?? user.emails[0]?.value;
}

/**
 * Get the display name from a SCIM user
 */
export function getDisplayName(user: ScimUser): string {
  if (user.displayName) {
    return user.displayName;
  }

  if (user.name?.formatted) {
    return user.name.formatted;
  }

  if (user.name?.givenName || user.name?.familyName) {
    return [user.name.givenName, user.name.familyName].filter(Boolean).join(' ');
  }

  return user.userName;
}

/**
 * Build a SCIM user object
 */
export function buildScimUser(
  userName: string,
  options?: {
    email?: string;
    name?: ScimName;
    displayName?: string;
    active?: boolean;
  }
): Omit<ScimUser, 'id' | 'meta'> {
  const user: Omit<ScimUser, 'id' | 'meta'> = {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName,
  };

  if (options?.email) {
    user.emails = [{ value: options.email, primary: true }];
  }

  if (options?.name) {
    user.name = options.name;
  }

  if (options?.displayName) {
    user.displayName = options.displayName;
  }

  if (options?.active !== undefined) {
    user.active = options.active;
  }

  return user;
}
