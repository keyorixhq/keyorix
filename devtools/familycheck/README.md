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

**Marker matching reads only the first marker line.** For each marker kind
(`family-check: intentional`, `family-check: new-member-verified`) the tool finds
the FIRST case-insensitive occurrence of the marker text anywhere in the PR body
(it need not start a line) and takes the rest of that one line. That line must
also contain the family's ID or interface name, or the marker counts as absent.
Later lines with the same marker are never read. Consequences:

- A PR that needs to dismiss or confirm several families can only do so for the
  family named on the first marker line of each kind; the others stay flagged
  (Mode A keeps nudging, Mode B keeps failing). Put the family that needs the
  marker first, or split the change so each PR touches one family.
- Do not quote the marker text earlier in the body (an example, a checklist
  template, a copied bot comment): the quoted occurrence becomes the first line
  and shadows the real one.
- The reason shown in the report is the text after the marker on that line, with
  a leading `—` or `-` removed. The prefix strip is case-sensitive, so a marker
  typed in another case still matches but keeps its own text in the reason.

"In scope" is deliberately narrow (see the 2026-09-05 report's own instruction
not to let this become noise): a family is in scope if its ID is in
`.github/family-check-scope.json`'s `families` list, OR if ANY of its
members' current file content matches a broad security-category keyword set
(dial/DNS/TLS, locking, audit logging, validation, authz/tenant checks,
context deadlines, credential handling). The keyword scan reads every
member's file, not just the touched ones — a brand-new member missing a
control is, by definition, likely to NOT contain that control's keyword, so
scoping Mode B by the new file's own content would systematically miss
exactly the cases it exists to catch.

The scope file also carries a `last_reconciled` date (`YYYY-MM-DD`) — the last
time a human (the quarterly asymmetry scan) confirmed the `families` list is
current. Mode B only gates a new member of a family ALREADY in that list; a
brand-new family the list doesn't know about is covered by nothing until the
next scan adds it. `familycheck` logs a non-blocking warning to stderr (never
fails the build) once `last_reconciled` is more than ~100 days old, missing,
or unparsable — see `warnIfScopeStale` in `main.go`. That warning is the
forcing function to re-run the scan, not a formality to silence.

## Marker lines: only the FIRST one per kind counts

`familycheck` looks for each marker (`family-check: intentional` and
`family-check: new-member-verified`) with a case-insensitive substring search over
the whole PR body and examines **only the first occurrence of that marker** (see
`dismissalReason` in `main.go`). The rest of that line, from the marker to the end
of the line, must name the family, by its ID or its interface name (also
case-insensitive). If the first line names a different family, the family is not
dismissed, even when a later line names it. The tool does not look at a second
line. The marker also does not have to start the line. Each marker kind is searched
separately, so an `intentional` line never confirms a new member.

Consequences, run against a PR that touches 1 of 2 members of each of two families,
`Alpha` and `Beta`, with no other changes:

| PR body | Outcome |
|---|---|
| `family-check: intentional — Alpha: only A1 has the bug` then, on the next line, `family-check: intentional — Beta: only B1 has the bug` | Alpha is dismissed (`(dismissed: Alpha — "Alpha: only A1 has the bug")`). **Beta is still reported** as an active Mode A nudge: the second line is never read. |
| `family-check: intentional — Beta: …` then `family-check: intentional — Alpha: …` | The mirror image: Beta is dismissed, Alpha is reported. |
| One line: `family-check: intentional — Alpha, Beta: only A1 and B1 have the bug` | Both are dismissed, each with that line's text as the reason. |
| No marker line | Both are reported, each with the `If intentional: …` hint. |

So when one PR needs several families dismissed or confirmed, put all of their
names on **one** marker line (`… — Alpha, Beta: <reason>`). Mode A is non-blocking either
way. For Mode B (`new-member-verified`) the same rule decides whether the exit code
is 1, so a second family confirmed on its own line still blocks the build.

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
