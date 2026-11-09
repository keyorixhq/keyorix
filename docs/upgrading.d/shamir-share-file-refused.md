## A Shamir share file that fails the owner and mode rule now stops the server

**Who is affected:** deployments with `storage.encryption.key_provider.type: shamir`, or a
`shamir` entry in `fallbacks`, that read shares from `shamir_share_files`. Shares from
`shamir_share_env` and its `_FILE` form were already refused.

**Old behaviour:** a too-open or foreign-owned share file was refused only by the startup
permission check. With `security.enable_file_permission_check` off, with
`security.allow_unsafe_file_permissions` on, or during the ADR-112 upgrade grace it was a warning
and the server unsealed anyway.

**New behaviour:** the file is refused whenever it is read, in every one of those modes, and in the
admin commands that unseal (`rotate-kek`, `migrate-provider`, restore). None of those settings
changes this. A loose share file that only warned before now stops the server from booting, and
the error names the file:

```text
shamir key provider: read share /etc/keyorix/share-1.hex: mode 0644 is too open (accessible to other users) -- refusing to trust it; ...
```

If a `fallbacks` provider is configured, the server logs that error and tries the next provider
instead of stopping, so a refused share can move the server onto a weaker provider. Check the
boot log for `key provider: shamir failed`.

The rule is the one every key-material secret follows. The file must be owned by the server's user
or by root, with mode `0600` or `0400`. The one exception is an orchestrator mount (Kubernetes
`fsGroup`, Docker `group_add`): owned by root, in a group the server belongs to, mode `0440`.

**What to do, before upgrading:** on each host, for every path in `shamir_share_files`:

```bash
stat -c '%a %U:%G %n' /etc/keyorix/share-*.hex
chmod 0600 /etc/keyorix/share-1.hex
chown keyorix /etc/keyorix/share-1.hex   # the user the server runs as
```

Do this with `chmod` and `chown`. `keyorix-server admin encryption fix-perms` unseals the KEK before
it touches any file, so after the upgrade it stops at the same refusal.
