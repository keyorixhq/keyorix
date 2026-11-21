### Internal

- `web/nginx.conf`: the internal `/_backend_health` and `/_backend_readyz` probe locations carry an inline `nosemgrep` for `generic.nginx.security.missing-internal.missing-internal` (both already declare `internal;`; Semgrep 1.172 reports a false positive). The `proxy_pass` lines keep their line numbers so the code-scanning alerts do not respawn.
