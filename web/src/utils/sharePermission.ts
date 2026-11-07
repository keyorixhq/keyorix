// What a secret share's permission actually allows. A "write" share lets the
// recipient update the value and metadata and rotate the secret (since #3001); it
// does not let them delete, share or administer it. Showing the bare word "write"
// is ambiguous (it reads as full control), so every place that shows a share-sourced permission uses this.

export const SHARE_WRITE_LABEL = 'Update value/metadata, rotate';

export function sharePermissionLabel(permission: string): string {
    if (permission === 'write') return SHARE_WRITE_LABEL;
    if (permission === 'read') return 'Read Only';
    return permission;
}

export const SHARE_OWNER_ONLY_HINT = "Only the secret's owner can change or revoke its shares";

// Who may edit or revoke a share on this page. The server lets only the secret's owner edit one
// (PUT /shares/{id}, core.requireShareAuthority), and only while still a live member of its project;
// a non-owner is refused (ErrShareNotOwner). Revoking (DELETE /shares/{id}) is also allowed to a
// holder of secrets.manage or an admin role at the secret's scope (#3992); this page does not offer
// that and keeps revoke to the owner. The share list
// names the owner as `createdBy` (a username, or "User <id>" when the name lookup failed), and
// transferring a secret re-owns its shares (INV-CORE-transfer-reowns-shares), so that name is the
// current owner. UI only: the server stays the enforcement point.
export function canManageShare(
    share: { createdBy: string },
    user: { id: number; username: string } | null | undefined
): boolean {
    if (!user) return false;
    return share.createdBy === user.username || share.createdBy === `User ${user.id}`;
}
