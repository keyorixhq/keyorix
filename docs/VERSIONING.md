# Versioning and deprecation policy

**Status: DRAFT for Andrei's review and signature. Not yet adopted.** Items marked
**[DECISION]** are choices only Andrei can make.

This page says what a Keyorix version number promises, what counts as a breaking
change, how a feature is deprecated before it is removed, and which upgrades we promise
and which we test. It builds on, and does not change:

- [`SECURITY.md`](../SECURITY.md) § Supported Versions: which minor lines receive
  security fixes (pre-1.0: current minor for all severities, previous minor for Critical
  and High). That table stays authoritative for support; this page does not extend or
  shorten it.
- [`SUPPORT.md`](../SUPPORT.md): release classes and LTS support after 1.0.
- [`UPGRADING.md`](UPGRADING.md): the per-release upgrade notes this policy requires.
- [`RELEASING.md`](../RELEASING.md) § Versioning: "Semantic Versioning" in one line.
  This page is the long form.

## 1. Version numbers

Keyorix releases are tagged `vMAJOR.MINOR.PATCH` (Semantic Versioning 2.0.0). One tag
drives the four SDK languages together (ADR-072); SDK versions track the API contract,
not the server release. A *minor line* is `vX.Y`: for `v0.96.3` the line is `v0.96`.

### Before 1.0 (today: v0.x)

SemVer allows anything to change in `0.y.z`. We promise more than that minimum, but less
than after 1.0:

| Release | What it may contain | What we promise |
|---|---|---|
| **Patch** `v0.96.x` | Bug fixes, security fixes, documentation | No breaking change as defined in section 2. No schema epoch change that raises the compatibility floor. Safe to roll forward and, within the same minor, back (checked for v0.96.1 and v0.96.3, see section 5). |
| **Minor** `v0.97.0` | New features, **and** breaking changes | Every breaking change is announced in the release's `### Security`/`### Changed`/`### Removed` changelog entry **and** in an `UPGRADING.md` section (the "breaking changes at a glance" table). Nothing breaks silently. |
| **Major** `v1.0.0` | The first declared-stable line | The rules for 1.x below begin. |

Pre-1.0 releases are development releases (`SUPPORT.md`): they have no declared support
period, so "breaking changes in a minor" is the stated way the project evolves until 1.0.
The deprecation period in section 3 still applies pre-1.0 to everything that can be
deprecated with an alias or a warning; it is skipped only for a change that cannot be
offered both ways (for example a security fix that removes an unsafe behaviour), and then
the entry says so.

### From 1.0

| Release | Allowed | Not allowed |
|---|---|---|
| **Patch** `1.x.Y` | Fixes only | Any breaking change; any new behaviour switched on by default |
| **Minor** `1.X.0` | New features, new optional settings, deprecations | Removal of a deprecated item before the period in section 3 ends; any other breaking change |
| **Major** `2.0.0` | Breaking changes, removal of deprecated items | Breaking change without a migration note and at least one prior minor that announced it (a security-driven exception is stated in the advisory) |

LTS lines (`SUPPORT.md`) receive security and data-loss/outage fixes only, as patch
releases; they never receive a breaking change.

**[DECISION]** whether the 1.0 minor cadence is fixed (for example quarterly) or stays
"as fixes are ready". `SECURITY.md` currently says we publish no release cadence.

## 2. What counts as breaking

A change is **breaking** if an operator or integrator who did nothing wrong has to change
something, or loses data or capability, after upgrading. Security *tightening* is breaking
when it refuses what used to work (`UPGRADING.md` has several: bind address, bootstrap
token length, CLI secret flags); it is still allowed pre-1.0 in a minor, and from 1.0 only
in a major unless it is a vulnerability fix, which ships under the `SECURITY.md` rules and
states the break in its advisory.

| Surface | Breaking (needs the process in section 3 or a major) | Not breaking |
|---|---|---|
| **HTTP API** (`/api/v1/...`, the OpenAPI document `server/http/handlers/openapi.yaml`) | Removing or renaming a path, method, field, enum value or error code; changing a field's type or meaning; making an optional request field required; tightening validation of previously accepted input; changing an HTTP status for an existing outcome; changing authentication or the permission an operation needs | Adding an endpoint, an optional request field or a response field; adding an enum value *where the schema documents the enum as open* |
| **gRPC API** (the `.proto` files) | Removing or renumbering a field or RPC; changing a field type; changing a status code | Adding fields, messages and RPCs |
| **CLI** (`keyorix`, `keyorix-server`, `keyorix-migrate`) | Removing or renaming a command or flag; changing a flag's meaning or default; changing an exit code for an existing outcome; changing the shape of `-o json` / `-o yaml` output (removed or retyped keys) | Adding a command, flag or output key; changing human-readable table text |
| **Configuration** (YAML keys, `KEYORIX_*` environment variables) | Removing or renaming a key or variable; changing a default so behaviour or security posture changes; making a previously valid value invalid (a start-up refusal that did not exist before) | Adding an optional key whose default keeps today's behaviour |
| **Database schema** | Anything an older binary of the *previous supported minor* cannot read or write correctly: a destructive migration, or a change that raises the compatibility floor (`system_metadata.schema_min_compatible_epoch`, ADR-101). Additive columns and tables that older binaries ignore safely are **not** breaking and do not raise the floor | Additive migrations that leave the floor unchanged |
| **Audit format** (audit-log rows, the hash chain, retention anchors, signed checkpoints, `verify-audit` / offline verify) | Any change after which a verifier of the previous version reports a valid chain as broken, or a new version cannot verify chains written by supported older versions. Example already in the changelog: the v2 audit retention anchor made v0.96.x read the chain as broken, so the floor was raised to epoch 3 (`UPGRADING.md` §6q) | Adding audit event types; adding fields old verifiers ignore |
| **Key-wrapping and encryption format** (DEK wrapped by KEK, key-provider blobs, ciphertext envelope, AAD binding) | Any change after which data or keys written by a supported older version cannot be read, or an older version cannot read newly written ones without a documented migration. Changes to the encryption layer also need an ADR first (`SECURITY.md` § Secure Development) | Adding a key provider; rotating keys (an operation, not a format change) |
| **Backup format** (`admin backup` archive, manifest `format_version`) | Dropping the ability to restore an archive written by a supported version; changing the manifest so older restore refuses it without notice. Restore refuses any `format_version` it does not recognise | New optional manifest fields |
| **Helm chart values, Compose files, image names and tags** | Renaming or removing a value, changing a default that changes security or availability, renaming an image | New optional values |
| **SDKs** | Per ADR-072, SDK versions track the API contract: a breaking SDK change follows the API rules above | Additive methods |

Machine-readable records of these surfaces exist and are enforced in CI where noted: the
OpenAPI document and generated client (contract tests), the config key list
(`internal/config/testdata/config_surface_leaves.txt`), the schema-epoch tripwire
(`internal/storage/schema_epoch_tripwire_test.go`, ADR-101) and the backup manifest
version check. This page states the policy; those files are what fail when it is broken.
Surfaces with no such check (CLI JSON output shapes, gRPC) rely on review; adding a guard
for each is open work (section 7).

## 3. Deprecation policy

A feature, flag, config key, API field or format is **deprecated** when we have announced
that it will be removed and a replacement (or a decision that none is needed) exists.
Deprecation is how every non-security breaking change in section 2 is introduced.

1. **Announce in the release that deprecates it.** Three places, all in the same release:
   - a `### Deprecated` entry in the changelog fragment (`changelog.d/`, assembled into
     `CHANGELOG.md` at release);
   - a section in [`UPGRADING.md`](UPGRADING.md) saying what to change, with the old and
     new form side by side;
   - a row in the table in section 4 of this page (the table is the single list of what
     is deprecated now).
2. **Warn at runtime.** The deprecated item must say so when it is used: a start-up
   deprecation warning for config keys (the existing mechanism, `DeprecatedSettingWarnings`
   logged by the server), a stderr notice for CLI flags, a notice on use for formats, and a
   `Deprecation` response header for HTTP API operations. A deprecation with no runtime
   signal is not complete. Warnings go to stderr or logs, never into `--json` output.
3. **Keep it working for at least two minor releases.** If it is deprecated in `vX.Y`, it
   still works, with the warning, in `vX.Y` and `vX.(Y+1)`, and may be removed no earlier
   than `vX.(Y+2)`. Pre-1.0 that is the minimum; there is no maximum. Removal pre-1.0 is
   a minor release with a `### Removed` entry. From 1.0, removal is only in a major release.
4. **Removal is a separate, announced step.** The removing release lists it under
   `### Removed` and in `UPGRADING.md`, and the row moves from section 4 to the removal
   record there. A removed config key must keep a clear start-up message naming the
   replacement, not a generic "unknown field" error, for at least one further minor
   release.
5. **Both names, same meaning.** While deprecated, the old form behaves exactly as before
   (or as the notes say), and when both old and new are set the new one wins and the old
   one is reported, as the config aliases already do.
6. **Exception, security.** A security fix may remove or change a behaviour without the
   full period (`SECURITY.md`: the fix and the advisory ship together). The advisory and
   the changelog `### Security` entry say what broke and how to adapt.
7. **Never shortened.** A published removal date or version is not brought forward. It may
   be pushed back.

Existing promises that are shorter than rule 3 are listed in section 4 with the proposed
correction. They are not silently kept or silently changed.

## 4. Current deprecations

Derived from the code and docs on `main` at the time of writing, not from memory. The
sources are named so the table can be re-derived: `internal/config/insecure_settings_aliases.go`
(`deprecatedSettingAliases`), `internal/config/config_storage.go`, `cli/cmd/run.go`,
`cli/cmd/output.go`, `server/admin/restore.go`, and the changelog (`### Deprecated`). A
test (`internal/docsdrift/versioning_deprecations_test.go`) fails if a config alias in the
code is missing from this table.

"Announced" is the first release whose notes mention the deprecation. "Earliest removal"
applies rule 3. "Current promise" is what the existing docs say today.

### Configuration keys

All are ADR-112 renames to the `insecure_` form: same meaning, a start-up warning when
the old name is used, the new name wins if both are set. Announced in **v0.96.0**
(first tag containing `deprecatedSettingAliases`). Earliest removal **v0.98.0**. The
current promise is "still accepts" with no removal version
(`CONFIGURATION.md`); this page sets the removal floor. `[]` marks a list entry.

| Deprecated key | Replace with |
|---|---|
| `security.allow_unsafe_file_permissions` | `security.insecure_allow_unsafe_file_permissions` |
| `security.login_lockout.disabled` | `security.login_lockout.insecure_disable_login_lockout` |
| `security.recover_admin.keyless_mode` | `security.recover_admin.insecure_keyless_admin_recovery` |
| `audit.siem.allow_private_network_target` | `audit.siem.insecure_allow_private_network_siem_target` |
| `audit.siem.allow_insecure_transport` | `audit.siem.insecure_allow_plaintext_siem_transport` |
| `evidence_delivery.webhook.allow_private_network_target` | `evidence_delivery.webhook.insecure_allow_private_network_evidence_target` |
| `evidence_delivery.webhook.allow_insecure_transport` | `evidence_delivery.webhook.insecure_allow_plaintext_evidence_transport` |
| `notifications.webhook.allow_private_network_target` | `notifications.webhook.insecure_allow_private_network_notify_target` |
| `notifications.webhook.allow_insecure_transport` | `notifications.webhook.insecure_allow_plaintext_notify_transport` |
| `dynamic_secrets.allow_private_network_targets` | `dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets` |
| `dynamic_secrets.allow_insecure_transport` | `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport` |
| `storage.encryption.key_provider.kms_allow_context_fallback` | `storage.encryption.key_provider.insecure_allow_kms_context_fallback` |
| `storage.encryption.key_provider.allow_weaker_fallback` | `storage.encryption.key_provider.insecure_allow_weaker_kek_fallback` |
| `storage.encryption.key_provider.fallbacks[].kms_allow_context_fallback` | `storage.encryption.key_provider.fallbacks[].insecure_allow_kms_context_fallback` |
| `storage.encryption.key_provider.fallbacks[].allow_weaker_fallback` | `storage.encryption.key_provider.fallbacks[].insecure_allow_weaker_kek_fallback` |
| `sso.providers[].trust_asserted_email` | `sso.providers[].insecure_trust_saml_asserted_email` |
| `sso.providers[].saml.allow_idp_initiated` | `sso.providers[].saml.insecure_allow_idp_initiated_saml` |
| `audit_checkpoints.disabled` | `audit_checkpoints.insecure_disable_audit_checkpoints` |

Note: `CONFIGURATION.md`'s table of renamed settings lists 15 of these 18; the three
`sso.providers[]` and `audit_checkpoints` rows are missing there (docs gap, listed in the
session report; not fixed in this PR).

| Deprecated key | Replace with | Announced | Earliest removal | Current promise |
|---|---|---|---|---|
| `storage.database.insecure_audit_skip_durable_sync` | `storage.database.audit_durability` (`true` = `standard`, explicit `false` = `strict`) | v0.97.0 (unreleased: `changelog.d/audit-durability-1-levels.md`, `UPGRADING.md` §6c) | **v0.99.0** under rule 3 | "one minor release" (changelog, `UPGRADING.md` §6c, `CONFIGURATION.md`, ADR-112 Amendment 3), i.e. removal in v0.98.0. **[DECISION]** extend to v0.99.0 to match rule 3 (recommended: lengthening is safe; the docs and ADR-112 wording then change from "one minor release" to "two"; proposed text in the session report) |

### CLI

| Deprecated | Replace with | Announced | Earliest removal | Runtime signal |
|---|---|---|---|---|
| `keyorix run --derive-names` | `--var NAME=secret-ref` (issue #1816) | v0.92.0 (changelog entry for the `run` behaviour change) | Already past the period. **[DECISION]** set a removal version | stderr `WARNING: --derive-names is deprecated ...` (`cli/cmd/run.go`) |
| `--format` on six commands (alias of `--output`/`-o`) | `--output` (`-o`) | v0.97.0 (unreleased: `changelog.d/cliux1-output-flag.md`) | **v0.99.0** | Hidden flag; cobra deprecation notice on stderr (`MarkDeprecated`, `cli/cmd/output.go`) |

### Formats

| Deprecated | Replace with | Announced | Earliest removal | Current promise |
|---|---|---|---|---|
| Backup archive **v1** (physical, SQLite-only, pre-2026-09-28 `admin backup`) | v2 archive (`format_version` 2); take a fresh backup | v0.95.0 (v2 became the only written format; `UPGRADING.md` §4) | Not before 1.0 | "v1 reading kept until 1.0" (`UPGRADING.md` §4, `design-b3-backup-v2.md` §3.6). `admin restore` prints a deprecation NOTE when it reads a v1 archive (`server/admin/restore.go`). v1 never restores into PostgreSQL. **[DECISION]** at 1.0: drop v1 reading (major-version event) or keep it for the first LTS |

### API

None. No operation in the OpenAPI document is marked `deprecated`, and the API has no
`Deprecation` header mechanism yet (rule 2 needs one before the first HTTP deprecation;
section 7).

## 5. The upgrade-path guarantee

### What we promise

| Path | Promise (pre-1.0) |
|---|---|
| **Patch to patch inside a minor** (`v0.96.1` to `v0.96.3`) | Supported. No migration step the notes do not describe. |
| **Previous minor to current minor** (`v0.96.x` to `v0.97.x`) | Supported. This matches the support window in `SECURITY.md` (current and previous minor). Read every `UPGRADING.md` section for the target release first; breaking changes are listed there. |
| **Across two or more minors** (for example `v0.95.x` to `v0.97.x`) | **Not promised pre-1.0.** Step through each minor. It often works mechanically (migrations run forward on start-up), but we do not state it, and the notes of every skipped release apply. |
| **Downgrade** (new binary back to old, same database) | **Not supported** across a release that raises the schema epoch floor. Rollback means restoring a backup taken before the upgrade (data written since is lost). Within one minor (patches) it works and is tested. |

After 1.0 (`SUPPORT.md`, which this page does not change): a direct upgrade from any LTS to
the next LTS is supported and tested; inside an LTS line, patches are a drop-in upgrade.
**[DECISION]** whether to also promise N-1 minor upgrades between LTS releases, and whether
to state a longer multi-minor window for non-LTS designated releases. Recommendation:
promise only LTS-to-LTS and previous-minor, as above, and publish anything wider only
after a test exists for it.

### What is tested, and what is only promised

Honest status of the evidence, from `UPGRADING.md` §3, `docs/operator/drill-upgrade.md`
and `reports/SESSION-UPGRADE-ROLLBACK-1.md` (session UPGRADE-ROLLBACK-1, 2026-10-22):

| Path | Tested? | How |
|---|---|---|
| `v0.96.1` to `v0.96.3`, SQLite, PostgreSQL 16 and the shipped Compose stack | Yes | Published images/binaries on the e2e VM, with a seeded database and DEK rotation. Seed intact, audit chain `VALID`. |
| `v0.96.3` back to `v0.96.1` in place (same epoch floor) | Yes | Starts and serves on the upgraded data; `verify-audit` valid in both directions. |
| Restore of a pre-upgrade backup (fresh target and in place) | Yes on SQLite and Compose/PostgreSQL | An in-place restore over a populated PostgreSQL target has a known defect, reported as a product bug (key files swapped before the load fails). Not guaranteed until fixed. |
| `v0.96.1` to `main` (v0.97 line), SQLite and PostgreSQL 16 | Yes (drill) | `docs/operator/drill-upgrade.md`. The reverse check, that the old binary now refuses with the schema-epoch message, is **not re-run yet**. |
| `v0.95.0` to `v0.95.2`, PostgreSQL | Yes | `UPGRADING.md` §3: one hop, Postgres only. |
| Any hop from `v0.94.x` or older, any SQLite multi-version skip | **No** | `UPGRADING.md` §3 says so: nobody has run it. |
| Skipping two or more minors | **No** | Not promised, not tested. |
| Helm chart upgrade or rollback | **No** | Not run in the sessions above. |
| HA rolling upgrade (several replicas on one PostgreSQL, mixed versions) | Partly | Guarded by the schema-epoch floor and database triggers (`UPGRADING.md` §6q, ADR-101). Not driven as a version-skew journey in the evidence reviewed. [VERIFY] |

The rule for adding to this table: a path may be listed as promised only when a test or
drill covers it, and the promise table above is changed in the same PR that adds the test.

## 6. How this ties to SECURITY.md

- **Support window vs. upgrade promise.** A security fix lands on the current minor and,
  for Critical and High, on the previous minor (`SECURITY.md`). The upgrade promise in
  section 5 is the matching one: previous to current is the path an operator on the
  previous minor takes when a Medium or Low fix requires "upgrade to the current minor".
  If the policy there ever changes, change section 5 in the same PR.
- **Security changes are exempt from the deprecation period** (rule 6), never from the
  announcement: the advisory (GHSA), the GitHub release notes and the `### Security`
  changelog entry say what changes.
- **Patch releases that carry a backport never contain a breaking change** (section 1),
  so a Critical or High fix on the previous minor can be applied without taking on the
  current minor's changes.
- **Version in the advisory.** Advisories name fixed versions as exact tags; a
  deprecated-and-removed item is never used as the reason to withhold a fix.
- **CRA.** Support periods, and the end-of-support date shown on a designated release,
  belong to `SUPPORT.md`. The CRA reporting path is the draft
  `docs/security/cra-reporting-process.md` (PR #3572; not linked here until it merges).
  This page makes no CRA claim.

## 7. Open items before adoption

- **[DECISION]** items above: release cadence from 1.0; the `audit_durability` alias
  period (extend to v0.99.0); a removal version for `--derive-names`; the fate of backup v1
  reading at 1.0; the wider multi-minor promise after 1.0.
- Add the missing three alias rows to `CONFIGURATION.md`'s renamed-settings table.
- Add an HTTP `Deprecation` header mechanism before the first API deprecation (rule 2).
- Guards still missing: a check that every `### Deprecated` changelog entry has a row in
  section 4; a check that CLI `-o json` key sets do not lose keys between minors.
- Proposed ADR-112 wording for the `audit_durability` alias period is in
  `reports/SESSION-DOCS-POLICY-LANE-1.md` (no ADR is edited in this PR).
- Re-run the multi-hop and Helm upgrade paths on the e2e VM before promising them.
