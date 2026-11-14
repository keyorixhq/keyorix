## Boot failures now exit 78 or 75, and the shipped systemd unit stops restarting on 78

`keyorix-server` used to exit 1 for every start-up failure, so under `Restart=always` a missing
passphrase file, a refused config or an unreachable KMS all became a restart every five seconds.
It now exits with a status that says which kind of failure it was, and prints one hint line last
on stderr (`keyorix-server: exit 78 ...` / `exit 75 ...`; no secret, no path):

| Exit status | Meaning | Shipped `deploy/edge/keyorix-server.service` |
|---|---|---|
| 78 | Refused configuration or missing/unusable key material: an operator must fix it. | `RestartPreventExitStatus=78`: not restarted; fix, then `systemctl restart keyorix-server`. |
| 75 | A dependency that may come back (cloud KMS or remote database unreachable). | Retried every `RestartSec`. |
| 1 | Everything else, as before. | Retried every `RestartSec`. |

**What to do when upgrading:**

- If you installed `keyorix-server.service` from `deploy/edge/`, copy the new file over yours
  (or add `RestartPreventExitStatus=78` and set `RestartSec=30`), then `systemctl daemon-reload`.
  The unit's `RestartSec` rose from 5 to 30: it is one delay for every restart, so after a crash
  the server is back after 30 s, not 5. systemd's growing delay (`RestartSteps=`) needs v254 and no
  minimum systemd version is documented, so the delay is fixed.
- A supervisor of your own (a `restart: always` container policy, a wrapper script, monitoring)
  that treats any non-zero exit as "retry" keeps working. One that alerts on exit status 1
  specifically should also match 78 and 75. No config key changed.
- Checked natively against the built binary (missing passphrase file, missing key file, unparseable
  config: 78; unreachable `aws-kms` endpoint: 75). A real systemd and a container start are pending
  e2e VM. See `docs/edge-deployment.md` §7a, "Start after a reboot".
