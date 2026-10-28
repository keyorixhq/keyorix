### Fixed

- Storage getters for notification channels, machine credentials, OIDC bindings, connector project bindings, secret templates, shares, SSO login state, permissions, alert escalation policies and rotation policies now return typed not-found sentinels (`storage.Err…NotFound`) for a missing row, so callers can classify with `errors.Is` instead of matching the translated error text. The error text is unchanged and a driver error never matches a sentinel. Handler migration follows in a separate change (ERRLOSS-SENTINELS-1).
