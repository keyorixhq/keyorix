# security.txt: source, hosting, renewal

[`security.txt`](security.txt) in this directory is the source of truth for the
RFC 9116 file Keyorix publishes. The policy it points at is
[`SECURITY.md`](../../SECURITY.md).

## Where it must be served

RFC 9116 binds the file to the host it is served from:
`https://keyorix.com/.well-known/security.txt`. That host is the marketing site,
which is not part of this repository, so **publishing is a hosting change that
this repository cannot make**. Copy the file unchanged to that path (and
`/security.txt`), over HTTPS, `Content-Type: text/plain; charset=utf-8`.

### Status and how to publish it

As of 2026-11-18 nothing in this repository serves the file: `web/public/` has no
`.well-known/` directory, no route in the product server returns it, and no
workflow deploys it. Whether the marketing site already carries a copy has not
been checked from here (the site is outside this repository).

Re-checked on 2026-11-28 against the server built from `origin/main` (`476a87938`, native
SQLite install, self-signed TLS): `curl -sk -o /dev/null -w '%{http_code} %{content_type}'
https://localhost:8080/.well-known/security.txt` prints `200 text/html; charset=utf-8`, and
`/security.txt` prints the same. The product server answers both paths with the dashboard's
`index.html` (the single-page-app fallback), not with this file. A scanner that fetches the
path therefore gets a 200 whose body is HTML, which is not a valid security.txt, and not a
clean 404 either.

**Open decision (Andrei):** keep the file off the product server (the reasons below still
hold, and the decision stays as it was) or serve it from the product build anyway. If it is
served from the product, the `Canonical` line cannot name `keyorix.com`, so it needs a
per-deployment value or an `Expires` the operator renews; neither exists today. Until that
is decided, publishing is the website task below.

To publish it on the website:

1. Copy `docs/security/security.txt` byte for byte to `/.well-known/security.txt`
   in the site's static root, and to `/security.txt` as RFC 9116 allows.
2. Serve both over HTTPS as `text/plain; charset=utf-8`, with no redirect to
   another host (the `Canonical` line must match the URL it is fetched from).
3. Check it from outside: `curl -sI https://keyorix.com/.well-known/security.txt`
   returns 200 and the content type above, and the body equals the repo file.
4. Put the renewal date (see Renewal) in whoever's calendar owns the site, since
   the repository test cannot see the deployed copy.

### Why it is not in the product web build

`web/` is the dashboard that customers run on their own hosts. Serving the file
there was considered and rejected:

- A customer's instance is not Keyorix's host. A `Canonical` line naming
  `keyorix.com` would be served from a different origin, which RFC 9116 treats
  as not authoritative, and a researcher would be pointed at us about a
  deployment we do not operate.
- The file carries an `Expires` date. A file baked into a versioned image goes
  stale in every image already deployed, and an expired file must be ignored by
  clients.
- It would need real changes: `web/nginx.conf` denies every path starting with a
  dot (`location ~ /\.`), so `/.well-known/` would return 403 until an exact-match
  location was added, and the embedded server build (`server/webui`) would need
  the same treatment.

## Renewal

`Expires` is set just under one year out (RFC 9116: less than a year). Renew it
at least 30 days before it lapses: bump `Expires` (never more than one year
ahead), republish the file, and note the new date in the commit message.
`deploy/security_txt_test.go` fails when the date is in the past or more than 366
days ahead and logs a warning from 60 days out. `scripts/check-security-txt-expiry.sh`
fails when `Expires` has passed or is less than 30 days away (`MIN_DAYS`). It is
meant for a scheduled job, not every PR: a calendar-dependent check on every PR
would turn the whole merge queue red on one day
(`docs/guard-rollout-contract.md`).

## Not included, on purpose

- `Encryption`: no PGP key or other report-encryption key is published. GitHub
  private vulnerability reporting is the encrypted-in-transit alternative. Add the
  field only when a key exists and is monitored.
- `Acknowledgments`: no researcher has been credited yet (see SECURITY.md,
  Hall of Fame). Add the field when the first advisory credits one.
- `Hiring`: not applicable.
