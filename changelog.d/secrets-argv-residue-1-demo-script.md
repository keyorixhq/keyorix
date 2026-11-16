### Security
- **`demo/vault-migration/run.sh` no longer puts the admin token, the login password or the dev Vault token on argv.** They go through a 0600 header file (`curl -H @file`), stdin (`--data-binary @-`) and `docker --env-file`; the argv-secret guard now also walks `demo/**/*.sh`.
