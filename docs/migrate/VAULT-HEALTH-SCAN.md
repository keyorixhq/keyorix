# Vault health scan — release readiness

This is the short "is it ready to ship" summary for `keyorix-migrate vault scan`, the free,
read-only Vault/OpenBao health check the website wants to link once it goes out in a
`keyorix-migrate` release. For the full technical reference (what each check does, the
read-only enforcement, the report format, sample output) see
[`docs/vault-health-scan.md`](../vault-health-scan.md) — this page doesn't repeat that content.

## Verdict: ready

Verified live against a real HashiCorp Vault dev-mode container (MIG-3, 2026-10-05): the
command ran end to end, produced all three report formats, and matched
`docs/vault-health-scan.md`'s own documented behavior exactly — same score formula, same
executive-summary shape, same "Not checked" handling, same footer convention. Exit code `0`.

What a customer actually runs:

```
keyorix-migrate vault scan --addr https://vault.example.com:8200 --output ./report
```

What they get: `report.md` / `report.json` / `report.html` — a 0–100 score with its formula
stated next to it, a top-5 risk list, a full findings table, per-check detail, a "Not checked"
section (never a silent gap), and a migration-readiness summary. Never writes to Vault, never
reads a secret value (enforced at the HTTP-client layer, not by review discipline — see the full
doc's "read-only guarantee" section for how that's proven).

## Rough edge found and fixed during this pass

**The JSON report's `findings`/`top_risks`/`not_checked` entries serialized with Go's raw
PascalCase field names** (`"ID"`, `"WhyItMatters"`, `"PolicyLine"`, ...) instead of the
snake_case convention the rest of the envelope already uses (`schema_version`, `generated_by`,
`vault_addr`, ...). `Finding`/`NotChecked` (`migrate/internal/healthscan/check.go`) never had
`json` tags at all. This is exactly the one surface the tool explicitly invites a customer to
hand to an external consumer ("Sharing the JSON with us" — send `report.json` for a second
opinion) — inconsistent casing there is a real integration blemish, not cosmetic.

Fixed by adding `json` tags to both structs and bumping `SchemaVersion` 2 → 3 (the field this
report format's own doc says exists precisely so a consumer can tell which shape it's reading).
Verified: `top_risks[0]`/`findings[0]` keys are now `id`/`title`/`severity`/`evidence`/
`why_it_matters`/`remediation`; `not_checked[0]` keys are `id`/`reason`/`policy_line`. Red/green
proven — a new test
(`TestWriteJSON_FindingAndNotCheckedFieldsAreSnakeCase`) fails against the pre-fix struct
(confirmed: round-tripped PascalCase keys verbatim) and passes after. Caught only because this
pass actually ran the command and read the JSON byte-for-byte — the existing
`TestWriteJSON_SchemaVersion` test never decoded into the nested arrays, so it couldn't have
caught this.

Since this hasn't shipped in a release yet, this is a free fix with zero compatibility cost —
exactly the right time to correct it.

## Known, accepted limitation (not a defect)

`versions.go`'s EOL/license table is a hand-maintained snapshot (`TableAsOf`, currently
`2026-09-01`) — G2's "no network call to HashiCorp" requirement means it can never be fetched
live. The report always surfaces `TableAsOf` in the version finding's own evidence text, so it
never implies more freshness than the build actually has. This is a deliberate design choice
(see that file's own doc comment), not something this pass needed to fix — flagged here only so
a future release-cut knows to glance at whether the table needs a refresh, not because it's
broken.

## Not in scope for this pass

- `root-tokens` always reports "not checked" by design (identifying root-policy tokens needs a
  `POST`, which this scanner's GET/LIST-only client structurally cannot issue) — documented
  behavior, not a gap to close.
- A dedicated `vault verify-access` CLI command (an ADR-114 access-equivalence check a customer
  could run standalone, mirroring what `scripts/demo/vault-migration-demo.sh` and the
  `TestAccessEquivalence_AppRoleGrantNeverExceedsVault` test harness already prove works) would
  be a natural next product surface, but is new work beyond "is the existing scan ready to
  ship" and wasn't built in this pass.
