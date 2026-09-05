# familycheck

The preventive half of the implementation-asymmetry scan (see
`keyorix-private/adversarial-review/IMPLEMENTATION-ASYMMETRY-SCAN-2026-09-05.md`).
The scan itself is detective — it finds asymmetries that already exist. This
is the per-PR control that's supposed to stop the next one from landing
un-noticed: PR #1449 added a rotation-lock mutex to AWS's `GenerateUpstream`
alone (a 7-member family), and PR #740 pinned GCP's secrets connector to a
project ID alone (a 4-member family) — both are exactly the "touched 1 of N
siblings" shape this tool flags.

Given two `asymanalyzer -json` outputs (one at the PR's base commit, one at
its head) plus the PR's changed-files list and body text, it flags two modes:

- **Mode A (nudge, non-blocking)**: the PR touches some but not all existing
  members of an in-scope family. Always exits 0. Dismiss with a PR-body line:
  `family-check: intentional — <Interface>: <reason>`
- **Mode B (gate, blocking)**: the PR ADDS a brand-new member to an existing
  family. Exits 1 until confirmed with a PR-body line:
  `family-check: new-member-verified — <Interface>: <what you checked>`

"In scope" is deliberately narrow (see the 2026-09-05 report's own instruction
not to let this become noise): a family is in scope if its ID is in
`.github/family-check-scope.json`, OR if ANY of its members' current file
content matches a broad security-category keyword set (dial/DNS/TLS, locking,
audit logging, validation, authz/tenant checks, context deadlines, credential
handling). The keyword scan reads every member's file, not just the touched
ones — a brand-new member missing a control is, by definition, likely to NOT
contain that control's keyword, so scoping Mode B by the new file's own
content would systematically miss exactly the cases it exists to catch.

## Usage

```
go build -o familycheck .
./familycheck \
  -base-families base.json -head-families head.json \
  -changed-files changed.txt -pr-body body.txt \
  -scope ../../.github/family-check-scope.json -repo-root <head checkout root>
```

Prints a Markdown report to stdout (post as a PR comment) and exits 1 iff an
unconfirmed Mode B finding exists — Mode A never fails the build.

## Replay-tested

Run against PR #1449's and PR #740's actual base/head commits before this
check went live — both fire as Mode A nudges naming exactly the untouched
siblings that turned out to matter. See the PR that added this file for the
replay transcript.
