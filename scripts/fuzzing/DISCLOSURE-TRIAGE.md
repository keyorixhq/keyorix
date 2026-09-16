# Supply-chain crash-feasibility triage

Before a fuzz finding in a **third-party library** becomes a disclosure (or an article
sentence), it has to pass a feasibility gate: *is this crash reachable through the library's
own public API, at the version under test, by an input a real caller could supply?* This is
the practice OSS-Fuzz-Gen's FalseCrashReducer and QuartetFuzz's "security-boundary respect"
principle formalize — and it's what stops us shipping a maintainer a report they'll (rightly)
close as "not a real bug." Published pipelines see **57–65% of raw LLM-fuzzer crashes turn out
infeasible**; this checklist is how we stay on the right side of that number.

A crash that fails this gate is a *harness artifact*, not a vulnerability. Do not disclose it,
do not count it in the ledger, do not name it in the article.

## The gate — every box must be checked

- [ ] **Public entry point.** The crashing call is reachable from an exported/public function
      of the library, not an internal-only helper we invoked directly. Trace the stack from a
      public API down to the crash site; write that path down.
- [ ] **Feasible input.** The triggering bytes are something a real caller could pass — a
      wire message, a file, a token — not a hand-forged internal struct that bypasses the
      library's own validation/constructors. (FalseCrashReducer's #1 false-positive cause:
      "inputs not feasible in normal execution.")
- [ ] **Preconditions respected.** Any setup/init/lifecycle the API documents or its real
      callers perform was performed. No skipped `New*()`, no half-initialized state the API
      would never see in production.
- [ ] **Version pinned + recorded.** The exact module version (a pseudo-version is fine) is
      captured. The finding is against *that* version; confirm it isn't already fixed on the
      library's default branch before reporting.
- [ ] **Our exposure, separately.** Whether *keyorix* is affected is a DIFFERENT question and
      does not gate disclosure. Record it either way: often our layer mitigates (e.g. the
      strict-DER guard in front of the RFC3161 path) while the library defect is still real for
      every other consumer. The article's whole point is that the vuln exists indirectly,
      regardless of our shield.
- [ ] **Deterministic reproducer.** A single saved input replays the crash/timeout on a clean
      checkout of the pinned version. Keep it PRIVATE.
- [ ] **Harness is itself correct.** The harness didn't cause the crash through its own bug —
      no stale state across iterations, no misuse of the API. (QuartetFuzz P1.)

## What to capture for the report (private until coordinated)

1. Library + exact version (pseudo-version / commit).
2. Public-API → crash-site call path (the stack, trimmed to the meaningful frames).
3. The minimized reproducer input (as a file; never inline in a public place).
4. Crash class (panic / OOB / unbounded CPU-DoS / alloc amplification) and observed cost
   (e.g. "~300-byte input → 4.8–9.7 s in Parse").
5. Whether it reproduces on the library's latest default-branch commit.
6. keyorix exposure + mitigation, stated separately.

## Disclosure discipline (unchanged, restated here so it's next to the gate)

- Coordinate with the maintainer first: private report, reasonable embargo, CVE if warranted.
- Land a temporary in-repo guard and/or a version pin on our side before any public mention.
- **Do NOT name an unpatched upstream finding** in the article, a talk, or a blog post until
  it is disclosed/patched or the maintainer agrees.
- Template + prior art: `claude/2026-09-11-digitorus-pkcs7-ber2der-dos-upstream-report.md`,
  `claude/2026-09-12-digitorus-disclosure-outreach.md`,
  `claude/2026-09-13-digitorus-disclosure-bundle-two-defects.md`.
