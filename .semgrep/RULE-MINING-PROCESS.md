# Mining fix history for recurring-bug-class rules

A one-off security fix closes the reported instance. It does nothing about the
next engineer (or the same one, six months later) writing the same mistake
into a different file. This process turns a *pattern* that recurred 3+ times
into a permanent, automated check — a CodeQL query or Semgrep rule — modeled
directly on a real fix, not a hypothetical.

Run this whenever a batch of security fixes lands (a review round, an
adversarial-audit sweep, a cluster of related CVE/bug-bounty reports), not
just once. The rule set should grow with the codebase's actual mistake
history, not stay frozen at whatever it started as.

## 1. Mine the fix history for recurring patterns

Sources: `keyorix-private/BUGS.md` (the round-by-round tracking doc — use it
for pattern *descriptions*, not as proof something is still broken; it goes
stale) and `git log` on this repo directly:

```
git log --oneline --all --grep="fix(security" -i
git log --oneline --all --grep="CWE-" -i
git log --oneline --all -E --grep="r1[0-9][0-9]|round [0-9]"
```

Read a spread of the actual fix diffs (`git show <sha>`), not just commit
messages — the message tells you *what* was fixed, the diff tells you the
*code shape*, which is what a query has to match.

**The bar: 3+ independent occurrences of the same underlying code shape.** A
single bad `if` condition in one handler is not a pattern — nothing to
mechanize. Two occurrences might be a coincidence. Three or more, especially
spread across files/rounds/authors, means the mistake is structural: something
about how this codebase is written makes it easy to make, and a human
reviewer is proven not to reliably catch it.

For each candidate pattern, write down:
- The concrete code shape (specific enough that you could describe it as a
  CodeQL predicate or a Semgrep pattern without more research)
- Every confirmed occurrence, with a commit SHA and file:line
- Which tool fits: **CodeQL** if the bug requires tracing a value across
  functions (taint/dataflow — an unbounded reader reaching a decoder several
  calls later, a TOCTOU across a `Get`/`Update` pair); **Semgrep** if it's a
  local, single-function/single-file structural match (a specific call
  missing a specific accompanying call, a fail-open error-handling shape)
- Your honest confidence that the pattern is low-noise. If you can already
  see 5 legitimate exceptions, it's not ready — narrow the shape or drop it.

Rank candidates by recurrence count and confidence. Don't force a rule for
every pattern you found — a bad rule (noisy, or worse, silently wrong) is
worse than no rule; it trains reviewers to ignore the tool.

## 2. Write the rule against real ground truth, not from memory

Write the query/rule using the concrete pre-fix and post-fix code you read in
step 1, not a paraphrase of it. Every rule needs a doc comment/message citing
the actual historical instances it's modeled on (see the existing entries in
`.semgrep/keyorix-rules.yml` and `.github/codeql/go-queries/*.ql` for the
expected format and level of detail).

## 3. Validate: positive control, then negative control

Both are required before a rule ships. Skipping either is how a rule ships
broken (silently never fires, or fires on everything).

**Positive control — does it actually catch the bug?**
Check out the pre-fix version of a known-real instance and confirm the rule
fires on it:

```bash
git show <fix-sha>~1:path/to/file.go > .scratch/fixture.go
```

For Semgrep, run the rule against the extracted file directly (mind
`paths: include/exclude` scoping — a fixture outside the rule's included
paths silently won't match; put it under the real path if the rule scopes
to one). For CodeQL, build a database against the pre-fix commit (a
temporary worktree at that commit, or `git show <sha>~1:...` extracted files
compiled standalone) and run `codeql database analyze --rerun`.

If the rule doesn't fire on the known-real historical bug, it's not ready —
iterate on the pattern until it does, testing against a minimal synthetic
fixture to isolate why (see the debugging notes in
`.github/codeql/go-queries/*.ql`'s own comments for examples of iteration
that was needed: `ActiveThreatModelSource` only modeling inbound request
bodies not outbound response bodies, `metavariable-regex` requiring a full
match not a substring search, etc.).

**Negative control — is it quiet on everything that's already fine?**
Run the rule against the *entire current codebase*, not just the file the
pattern came from:

```bash
semgrep scan --config=.semgrep/keyorix-rules.yml <paths>
# or
codeql database analyze <db> <query.ql> --format=csv --rerun
```

Every hit here needs individual investigation — don't assume a hit is either
"the rule works" or "false positive" without reading the actual code and
tracing how the value is used. This step is where new, previously-unknown
bugs get found (a hit that's real and wasn't part of the original 3+ you
started from) — this has happened every time this process has been run; it
is the actual point of the negative-control sweep, not a formality. It's
also where you find the rule is too broad (an unrelated but structurally
similar pattern, like an *additive*-only permission field matching a rule
written for a *subtractive* fail-open field) and needs narrowing.

For each real hit:
- **Genuine new bug** → fix it, in the same PR as the rule. Don't ship a rule
  that immediately fails its own gate.
- **Confirmed safe, rule is right to flag it as worth a second look but this
  instance is fine** → add a `// nosemgrep: <rule-id> -- <specific reason>`
  comment (Semgrep) explaining *why*, matching this repo's existing
  suppression convention. A vague reason is not acceptable — write the reason
  someone six months from now, with no memory of this investigation, would
  need to trust the suppression instead of re-litigating it.
- **Rule is too broad** → narrow it (a keyword list, a path scope, an
  additional structural constraint) and re-run both controls.

A rule doesn't ship until negative control is clean (zero unexplained
findings) and positive control fires on real historical code — see the
existing rules for the target bar (each one in this repo was iterated to
exactly zero false positives against the current tree, not "mostly quiet").

## 4. Wire it in, make it count

- CodeQL queries: add the `.ql` file to `.github/codeql/go-queries/` — no
  workflow change needed, `codeql.yml`'s `queries: +./.github/codeql/go-queries`
  picks it up automatically.
- Semgrep rules: add to `.semgrep/keyorix-rules.yml`. If it's WARNING/ERROR
  severity and passed negative control, it runs in the **blocking** step of
  `.github/workflows/semgrep.yml` automatically — no separate opt-in. Use
  INFO severity only for a rule that's deliberately expected to match
  existing, accepted code (a structural nudge, not a violation) — see
  `keyorix-new-remotestorage-unsupported-stub` for the pattern.
- If the rule found and fixed a real bug in step 3, that fix PR must carry a
  regression test (enforced for any `fix(security):`-titled PR by
  `.github/workflows/security-fix-regression-test.yml`) — the rule proves the
  *pattern* is gone; a test proves the *behavior* is actually fixed.

## Known limits of this process

- A rule only catches what it's shaped to catch. A CodeQL query's own
  heuristic (e.g. tracing validation to a *field read*) can miss a fix that
  validates a raw pre-parse value instead — verify a fix with an actual
  integration test through the real API boundary, not just by re-running the
  query and expecting zero hits.
- Some recurring patterns don't reduce to a static rule at all — check-then-
  act races with no single "blessed helper" to require, or missing DB unique
  constraints (the ground truth lives in schema tags, not the call site) are
  better served by a purpose-built Go test walking the AST/schema than by a
  generic query. Don't force every pattern into CodeQL/Semgrep just because
  that's the default tool — pick the mechanism that actually gets you to
  zero-noise.
- This process finds patterns that have already bitten the codebase 3+ times.
  It does not replace threat modeling or adversarial review for genuinely new
  bug classes that haven't recurred yet — it's a complement to that work, not
  a substitute.
