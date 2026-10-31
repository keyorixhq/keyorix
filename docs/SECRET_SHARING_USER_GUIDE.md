# Secret Sharing User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Sharing Secrets](#sharing-secrets)
4. [Managing Permissions](#managing-permissions)
5. [Group Sharing](#group-sharing)
6. [Accessing Shared Secrets](#accessing-shared-secrets)
7. [Self-Management](#self-management)
8. [Security Best Practices](#security-best-practices)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

## Introduction

Secret sharing in Keyorix allows you to securely collaborate by giving other users controlled access to your secrets. This feature enables teams to work together while maintaining security and auditability.

### Key Features
- **Secure Sharing**: End-to-end encryption maintained during sharing
- **Permission Control**: Grant read-only or read-write access
- **Group Support**: Share with entire teams or groups
- **Audit Trail**: Complete logging of all sharing activities
- **Self-Management**: Users can remove themselves from shares
- **Real-time Updates**: Changes are immediately reflected across all interfaces

### Who Can Share Secrets?
- **Secret Owners**: Can share their secrets with others, as long as they are a
  member of the secret's project (they hold a role in that project). A global
  role, such as the bootstrap `admin`, does not make anyone a member of a
  project: give yourself a project role first (for example `project_admin`).
- **Users with Write ("Read & Write") Permission**: Can read the secret, update its value and
  metadata (description, tags, type), and rotate it. Nothing else: see the next section.
- **Users with Read Permission**: Can view shared secrets but cannot modify them

### How a Share Combines with a Project Role
A share can only go to a **member of the secret's project**, and it only
applies while the recipient is still a member. For that member, the
permission on the shared secret is the **higher** of the two:

| Project role gives | Share gives | Effective on that secret |
|---|---|---|
| read (e.g. `project_viewer`) | none | read |
| read | `read` | read |
| read | `write` | read **+ update value and metadata, rotate** (the share elevates them for these three only) |
| write (e.g. `project_developer`) | `read` | everything the role allows (the role already covers it) |

- The elevation covers that one secret only, never the rest of the project.
- A `write` share elevates exactly three actions: **update the value**,
  **update metadata** (description, tags, type), and **rotate**. Everything
  else that needs `secrets.write` still needs a project role, even with a
  `write` share: suspend and resume, changing the expiry or the read limit,
  moving the secret, rolling it back to an older version, transferring
  ownership, classification, auto-rotation settings, dependencies and version
  comments. The refusal says so: "A share on this secret only lets you update
  its value and metadata or rotate it."
- A share never grants delete, restore, secret management (`secrets.manage`:
  ACLs, schedules, retention) or the right to share the secret onward. Only
  the owner can share, change or revoke shares, including other people's.
- Revoking a share removes exactly the elevation. The recipient keeps whatever
  their role gives them (in the table above, a `project_viewer` keeps read).
- An expired share grants nothing, even before it is cleaned up.
- A share to someone who is later removed from the project stops applying at
  once.
- Every action a share made possible (one the recipient's role alone would
  not allow) is audited as `share_access_elevated` when it is performed,
  naming the action (`secret.update`, `secret.update_metadata`,
  `secret.rotate`), the secret, the share ID and the recipient. A refused or
  failed request writes no such event, and neither does an action the
  recipient's role already allowed. Share create, update and revoke events
  name the share ID too.
- Opening the share list (`GET /api/v1/shares`, `GET /api/v1/shares/owned`)
  names each secret you can read. When some of those names are readable only
  because of a share, the list call writes ONE `share_access_elevated` event
  with action `shares.list`: how many secrets, and the secret and share IDs
  (the first 50; `truncated` says when there are more). It does not write one
  event per secret on the page.

`keyorix secret access --id N` (and the API's `GET /secrets/{id}/access`) shows
each user's **effective** level on the secret, the grant that gives it, and every
grant they hold. A viewer elevated by a write share shows as `write`, from
`direct_share`, with grants `role:read, direct_share:write`. Role grants need
`users.read` at the project and ACL grants need `secrets.manage` on the secret;
without them those grants are left out and the report says it is incomplete: the
CLI prints `WARNING: this list is incomplete` with the reasons, and the web panel
shows a "This list is incomplete" banner. No built-in project role holds
`secrets.manage`, so project members normally see that warning. Deactivated
accounts that still hold a grant are listed on purpose, because the grant applies
again if the account is reactivated.

If a share is refused, the error says why: "you are not a member of this
secret's project" (the owner needs a project role) or "the recipient is not a
member of this secret's project" (the recipient needs one).

A user's access to a secret is the **union** of every path that grants it: being the
owner, a direct share, a group share, a per-secret ACL, and a role on the secret's
project. A share *adds* a path; **revoking it removes only that path.** If the
recipient's project role already grants read (every built-in project role,
including `project_viewer`, does), they keep reading the secret after the share is
revoked: the share was not what gave them read. To end their access, also remove
the role (`keyorix rbac remove-role`). A `write` share does elevate a read-only
role on that one secret (see the table above), and revoking it removes exactly
that elevation. `keyorix secret access` shows the effective level of each user,
including role-derived access (see above).

## Getting Started

### Prerequisites
- Active Keyorix account
- Appropriate permissions to access secrets
- Knowledge of usernames or group names you want to share with

### Accessing the Sharing Interface

#### Web Interface
1. Open **Secrets** in the sidebar
2. Click the share icon (tooltip "Share") on the secret's row, or open the secret
   and click **Share**. Both appear only if your project role lets you write secrets.
3. The **Sharing** column of the list shows a share icon with "N shares" (or
   "Shared with you" on your own list) for shared secrets, and "Private" for
   the rest
4. **Sharing** in the sidebar opens the Sharing Management page, where you
   review, edit and revoke the shares you created

#### CLI Interface
All sharing commands are under `keyorix share` (`create`, `list`, `update`, `revoke`,
`self-remove`, `shared-secrets`, `group-shares`); see the
[CLI reference](cli-reference.md#keyorix-share).

#### API Interface
See the [API Documentation](SECRET_SHARING_API.md) for programmatic access.

## Sharing Secrets

### Basic Secret Sharing

#### Via Web Interface
1. **Select Secret**: Navigate to the secret you want to share
2. **Click Share**: Click the "Share" button (or the share icon on the list row)
3. **Choose Recipient**: Type a name or username in the "Recipient" field and
   pick from the suggestions. The suggestions are the active members of the secret's project,
   because a share can only go to a project member. A project-only admin sees them
   too; no global role is needed. If you have no role in the project that allows
   sharing, the dialog says so instead of listing anyone.
4. **Set Permission**: Choose "Read Only" or "Read + update value/metadata, rotate"
   (the `write` share described above)
5. **Set Expiry** (optional): "Access expires" defaults to "Never (permanent)";
   1 hour, 24 hours, 7 days and 30 days are also offered
6. **Confirm**: Click "Share" to complete

#### Via API
```bash
curl -X POST "https://api.keyorix.com/api/v1/secrets/123/share" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 456,
    "permission": "read"
  }'
```

### Understanding Permissions

#### Read Permission
**What recipients can do:**
- View secret name, type, and metadata
- Access the secret value
- View secret version history
- See when the secret was last updated

**What recipients cannot do:**
- Modify the secret value
- Update metadata or tags
- Share the secret with others
- Delete the secret

#### Write Permission
**What recipients can do:**
- Everything from read permission
- Update the secret value
- Modify metadata and tags
- Create new versions of the secret

**What recipients cannot do:**
- Delete the secret
- Change sharing permissions
- Share with others (only owners can share)

### Sharing Multiple Secrets

The web UI shares one secret at a time: with several secrets selected, its
**Share** button is disabled ("Share each secret individually — bulk sharing is
not supported"). Use the CLI or the API to share several secrets.

## Managing Permissions

### Viewing Current Shares

#### List Shares for a Secret
```bash
curl -X GET "https://api.keyorix.com/api/v1/secrets/123/shares" \
  -H "Authorization: Bearer your-token"
```

#### List All Your Shares
```bash
curl -X GET "https://api.keyorix.com/api/v1/shares" \
  -H "Authorization: Bearer your-token"
```

### Updating Permissions

#### Upgrade Permission (Read → Write)
```bash
curl -X PUT "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"permission": "write"}'
```

### Revoking Access

#### Remove Specific User Access
```bash
curl -X DELETE "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer your-token"
```

## Group Sharing

### Understanding Groups
Groups allow you to share secrets with multiple users at once. When you share with a group:
- All current group members gain access immediately
- New group members automatically gain access
- Removed group members automatically lose access
- Permission level applies to all group members

### Sharing with Groups

#### Via Web Interface
The Share dialog searches users only; it has no group option. Share with a
group through the CLI (`keyorix share create --is-group`) or the API. Group
shares then appear in the Sharing Management page, where "Groups" filters
the list.

#### Via API
```bash
curl -X POST "https://api.keyorix.com/api/v1/secrets/123/share" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 10,
    "is_group": true,
    "permission": "read"
  }'
```

### Managing Group Shares

#### List Group Shares
```bash
# filter the response for group shares
curl -X GET "https://api.keyorix.com/api/v1/shares?recipient_type=group" \
  -H "Authorization: Bearer your-token"
```

### Group Membership Changes

When group membership changes:
- **User Added**: Automatically gains access to all secrets shared with the group
- **User Removed**: Automatically loses access to all group-shared secrets
- **Group Deleted**: All shares with that group are automatically revoked

## Accessing Shared Secrets

### Finding Shared Secrets

#### Web Interface
- Shared secrets appear in your main secrets list
- Look for the share icon and "Shared with you" in the **Sharing** column
- The list has no "shared with me" filter
- The owner is shown under the modified date ("by <owner>")

### Working with Shared Secrets

#### Viewing Shared Secret Details
```bash
# Get secret information
keyorix secret get --id 123


# View secret versions
keyorix secret versions --id 123
```

#### Modifying Shared Secrets (Write Permission Required)
```bash
# Update secret value (typed at a hidden prompt, so it never lands in shell history)
keyorix secret update --id 123 --interactive

# Update secret value from a file (relative path, not a symlink)
keyorix secret update --id 123 --from-file ./new-secret.txt

# Change the expiration
keyorix secret update --id 123 --expires "2027-01-01T00:00:00Z"
```

### Understanding Sharing Context

When viewing a shared secret, you'll see:
- **Owner Information**: Who owns the secret
- **Last Modified**: When the secret was last updated
- **Version History**: All versions (if you have read access)
- **Who can access**: each user's effective level and the grant behind it (see
  `keyorix secret access` above)

## Self-Management

### Removing Yourself from Shares

Sometimes you may want to remove yourself from a shared secret. The web UI has
no "Leave share" action; use the CLI (`keyorix share self-remove`) or the API:

#### Via API
```bash
curl -X DELETE "https://api.keyorix.com/api/v1/secrets/123/self-share" \
  -H "Authorization: Bearer your-token"
```

### The Sharing Management Page

**Sharing** in the sidebar lists the shares you created ("Shares you created"):
- Search recipients or creators
- Filter by recipient type (All Types, Users, Groups) and permission
- Edit a share's permission and expiry (pencil icon) or revoke it (trash icon,
  "Revoke access"). Only the secret's owner can; for everyone else both icons
  are disabled with the hint "Only the secret's owner can change or revoke its shares".
- **Select** switches on checkboxes, then **Revoke** removes the selected shares

## Security Best Practices

### For Secret Owners

#### 1. Principle of Least Privilege
- Grant the minimum permission level required
- Regularly review and audit who has access
- Remove access when no longer needed

#### 2. Monitor Access Patterns
- Review audit logs regularly
- Watch for unusual access patterns
- Set up alerts for sensitive secrets

#### 3. Use Groups Wisely
- Share with groups rather than individual users when possible
- Keep group membership up to date
- Use descriptive group names

### For Recipients

#### 1. Respect Access Levels
- Don't attempt to exceed your permission level
- Report any access issues to the secret owner
- Use shared secrets responsibly

#### 2. Secure Your Account
- Use strong authentication
- Keep your credentials secure
- Report suspicious activity immediately

#### 3. Clean Up Access
- Remove yourself from shares you no longer need
- Notify owners if you no longer require access
- Keep your profile information current

### General Security

#### Network Security
- Always use HTTPS for web access
- Use secure networks when accessing shared secrets
- Consider VPN for sensitive operations

## Troubleshooting

### Common Issues

#### "Permission Denied" Errors
**Problem**: Cannot access a shared secret
**Solutions**:
1. Verify you have the correct permission level
2. Check if the share has been revoked
3. Confirm the secret still exists
4. Contact the secret owner

#### "Share Already Exists" Errors
**Problem**: Cannot create a share that already exists
**Solutions**:
1. Check existing shares for the secret
2. Update the existing share instead of creating new one
3. Verify recipient information is correct

#### "User Not Found" Errors
**Problem**: Cannot share with specified user
**Solutions**:
1. Verify the username is correct
2. Check if the user account is active
3. Ensure the user has access to the system
4. Try using user ID instead of username

### Performance Issues

#### Slow Loading of Shared Secrets
**Solutions**:
1. Use pagination for large lists
2. Apply filters to reduce result sets
3. Check network connectivity
4. Clear browser cache (web interface)

#### API Rate Limiting
**Problem**: Too many requests error
**Solutions**:
1. Implement exponential backoff
2. Reduce request frequency
3. Use batch operations when available
4. Contact support for rate limit increases

### Getting Help

#### Self-Service Resources
- Check the [API Documentation](SECRET_SHARING_API.md)
- Review [Security Considerations](security/architecture.md)
- Browse [Workflow Examples](SECRET_SHARING_WORKFLOWS.md)

#### Support Channels
- **Documentation**: Check this guide and API docs
- **Community Forum**: Ask questions and share experiences
- **Support Tickets**: For technical issues and bugs
- **Emergency Contact**: For security incidents

## FAQ

### General Questions

**Q: Can I share a secret with someone who doesn't have a Keyorix account?**
A: No, all recipients must have active Keyorix accounts to receive shared secrets.

**Q: What happens if I delete a secret that's shared with others?**
A: The secret is deleted for everyone, including all users it was shared with. They will lose access immediately.

**Q: Can recipients share secrets with others?**
A: No, only the original owner can share secrets with additional users or modify sharing permissions.

**Q: Is there a limit to how many people I can share a secret with?**
A: There are reasonable limits to prevent abuse. Contact support if you need to share with a large number of users.

### Permission Questions

**Q: What's the difference between read and write permissions?**
A: Read permission allows viewing the secret and its metadata. Write permission additionally allows modifying the secret value and metadata.

**Q: Can I give someone permission to share my secrets?**
A: No, sharing permissions cannot be delegated. Only the original owner can manage sharing.

**Q: How do I know what permission level I have for a shared secret?**
A: Open the secret: the "Who can access" panel lists each user's effective level (global admins are not listed). From the CLI, run `keyorix secret access --id N`.

### Security Questions

**Q: What happens if someone's account is compromised?**
A: Immediately revoke all shares with that user and report the incident. Change any secrets they had access to.

**Q: Can I see who has accessed my shared secrets?**
A: Yes, audit logs show all access attempts and successful accesses to your shared secrets.

### Technical Questions

**Q: Can I automate sharing through the API?**
A: Yes, the full sharing functionality is available through the REST API. See the API documentation for details.

**Q: Can I share secrets across different environments?**
A: Yes, sharing works across all environments within the same Keyorix instance.

**Q: What happens during system maintenance?**
A: Shared secrets remain accessible during maintenance. Sharing operations may be temporarily unavailable during updates.

---

*Last updated: July 22, 2025*
*Version: 1.0.0*