### Security
- **`keyorix-server admin recover-admin` no longer lifts a suspension or deprovisioning silently.** An admin
  account that is `suspended` or `deprovisioned` (or whose `account_state` is a value Keyorix does not
  recognise, which login already fails closed on) is now refused by default, with nothing changed and an
  `admin.recover_admin_failed` audit event. The new `--force-unsuspend` flag recovers it anyway; it still
  requires the recovery key and a global-admin target, and the audit event and the notification to every
  admin then name the state that was lifted. The state is checked again on the row lock inside the reset
  transaction, so a suspension that lands during the run (for example under the admin `--force` lock
  bypass) is not lifted either. Scripts that relied on recover-admin reactivating a suspended admin must
  add `--force-unsuspend`.
