# Short-lived PostgreSQL credentials (dynamic secrets)

Instead of one long-lived database password shared by every instance, an application asks
Keyorix for a credential. Keyorix creates a LOGIN role in PostgreSQL with a time limit and
drops it when the lease ends or is revoked. Each caller gets its own credential, so you can
revoke one without touching the others, and the audit log shows who asked for which one.

The same engine exists for MySQL, MongoDB, Redis, AWS STS, GCP, Azure and Kubernetes
ServiceAccount tokens ([ADR-035](./adr-035-dynamic-secrets.md),
[ADR-058](./adr-058-kubernetes-dynamic-secrets.md)). This page shows PostgreSQL.

## 1. Create a role for Keyorix to use (database owner)

Keyorix needs one privileged connection, used only to create and drop the temporary roles.
Give it only that: for example `CREATEROLE`, plus the ability to grant the specific privileges
you will hand out. Do not use a superuser.

## 2. Register the target (project admin)

The admin connection string is never a command-line flag, so it does not land in shell history.
Pass it in the environment, or type it at the hidden prompt:

```sh
export KEYORIX_DYNAMIC_ADMIN_DSN='postgres://keyorix_admin:...@db.internal:5432/payments?sslmode=verify-full'

keyorix dynamic-secret create \
  --name payments-reader \
  --project-id 12 --environment-id 34 \
  --backend postgres \
  --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};' \
  --default-ttl 900 --max-ttl 3600 --max-active-leases 20
```

`{{name}}` is replaced with the generated role name. Keyorix encrypts the connection string at
rest and never returns it. `--max-ttl` is a hard ceiling and `--max-active-leases` limits how
many credentials can exist at once.

The connection must verify the database server's certificate: use `sslmode=verify-full` (or
`verify-ca`). `sslmode=disable`, `allow`, `prefer` and `require`, and a DSN without `sslmode`
(the driver then uses `prefer`), are refused when the config is saved; for MySQL the same rule
accepts only `tls=true`. The certificate must be trusted by the Keyorix server's system trust
store (or its `PGSSLROOTCERT` / `~/.postgresql/root.crt`), since the DSN cannot name a CA file.
Only the operator can allow an unverified connection, for every dynamic-secret backend at once,
with `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport: true`; every such save,
issue and connection is then audited or logged with a WARNING. A config stored before this rule
keeps issuing for one release with a WARNING and an audit event on every issue
([upgrade note](upgrading.d/sql-admin-dsn-transport-policy.md)).

The server also refuses connection-string options that read a file on the Keyorix server (such as
`sslrootcert` or `tlsCAFile`) or that use the server's own ambient credentials. If a config stops
issuing because of this, list the affected configs with
`keyorix dynamic-secret refused-dsn --project-id 12` and fix each with
`keyorix dynamic-secret set-admin-dsn <config-id>`.

## 3. Get a credential (application or operator)

```sh
keyorix dynamic-secret issue <config-id> --ttl 600
```

The username and password are shown once. They stop working at expiry.

An application calls the API (or SDK) at start-up and opens its connection pool with the
result. Size the TTL to your reconnect behaviour: pools hold open connections, and a new
connection after the role is dropped fails unless the application asks for a new credential.

## 4. Operate

| Task | Command |
|---|---|
| See active leases | `keyorix dynamic-secret leases <config-id>` |
| Extend a lease (up to the config's max TTL) | `keyorix dynamic-secret renew <lease-id> --ttl 600` |
| Revoke one caller | `keyorix dynamic-secret revoke <lease-id>` |
| Revoke every credential from a config | `keyorix dynamic-secret revoke-all <config-id> --yes` |
| Set the config's classification | `keyorix dynamic-secret classify <config-id> --level restricted` |

## 5. A test worth running before you rely on it

1. Issue two credentials from the same config.
2. Connect with both.
3. Revoke one.
4. Confirm that new connections with the revoked one fail and the other still works.
5. Restart the application and check that it obtains a fresh credential.

This tests the whole path, not only that the feature exists.

## Notes

- Revoking a lease drops the role. Sessions that were already open may need to be ended
  separately, depending on your PostgreSQL setup; check this in your environment.
- Combine this with a workload identity (see
  [Kubernetes ServiceAccount authentication](./k8s-serviceaccount-auth.md)) so the application
  needs no stored Keyorix token either.
- The cloud backends (`aws-sts`, `gcp`, `azure`, `kubernetes`) issue self-expiring tokens that
  cannot be cancelled early (the Kubernetes backend can, if you set `"revocable": true`); use
  short TTLs for them.
