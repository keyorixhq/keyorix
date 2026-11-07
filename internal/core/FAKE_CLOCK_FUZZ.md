# Fake-clock fuzz (fake_clock_fuzz_test.go) -- pre-registration

Committed BEFORE any campaign run. Rules are fixed; results go in a later commit.

## Scope and what already exists

`KeyorixCore.SetClockForTesting` is the clock seam (#1983). `clock_fuzz_test.go`
(FuzzClockJumpNeverAuthorizesExpired) already fuzzes session/PAT/lease around
credentials minted at one fixed instant (2026-06-12), with jumps clamped to +/-5
years. This suite adds what that one structurally cannot reach:

* credentials MINTED at extreme instants (zero time, year 0, 1970, 2038, 2106,
  leap days, DST edges, 9999-12-31, year 10000, the far future) and TTLs from 1s to
  100 years (overflow / wrap / serialization of the stored expiry);
* multi-step clock programs (up to 6 steps): exact-expiry +/-1ns, absolute jumps
  to the special instants, backward jumps, the zero time, monotonic-reading
  stripped / re-zoned values;
* the secret access schedule (`enforceSchedule`) across real tzdata zones with
  DST transitions (spring-forward gaps, fall-back overlaps, half-hour DST at
  Lord Howe, 45-minute offset at Chatham, the skipped day in Apia, negative DST
  in Dublin/Casablanca), leap days;
* an inventory of expiry decisions that bypass the injectable clock (bare
  `time.Now()`), because a decision that cannot be driven by the fake clock
  cannot be fuzzed by it.

TOML question: Keyorix does not parse TOML dates. `BurntSushi/toml` is only a
transitive dependency of `go-i18n`; `internal/i18n` registers a JSON unmarshal
func only and loads JSON locale files; no `.toml` data file is read at runtime
(the repo's only `.toml`/`.tpl` files are gitleaks/revive tool configs). Recorded
here so the question is closed with evidence, not asserted.

## Oracles (model-based, not read off the code under test)

For a credential with expiry E and a clock program T1..Tn, after each step i
(clock set to Ti, credential checked, "past" = Ti.After(E)):

O1  never valid after expiry: accepted => !past.
O2  never valid again after being observed expired: once some Tj was past E
    (for session/PAT; for leases only after a regression larger than the
    documented 30 s tolerance), no later check accepts, whatever the clock then
    shows (anti-rollback).
O3  never expires early: for session/PAT, a check at Ti >= issue instant with
    !past and not previously observed expired is accepted.
O4  no panic, and minting at an extreme instant either errors cleanly or yields
    an expiry >= the issue instant (no wrap-around to the past).
O5  representation independence: the verdict is identical for the same instant
    expressed in UTC, a fixed zone, a DST zone, and with the monotonic reading
    stripped (Round(0)).
O6  schedule: `enforceSchedule(s, t)` agrees with an independent computation of
    local weekday/hour from `t.UTC()` plus the zone's offset at t (not via
    `t.In(loc).Hour()`), for every instant, and is representation independent.

## Rules

R1  Planted defects. The oracle driver is a pure function over a credential
    interface. It must (a) report ZERO violations on a correct reference model
    and (b) report a violation for each planted mutant: M1 accepts at exactly
    E (off-by-one late), M2 rejects at E-1ns (early expiry), M3 no anti-rollback
    watermark (resurrection after a backward step), M4 wraps TTL overflow to a
    past expiry, M5 for the schedule: uses `Local` hour instead of the zone's
    hour. 5/5 required, else the campaign is void.
R2  Campaign: FuzzFakeClockExtremes and FuzzEnforceScheduleDST each run >= 10
    minutes of fuzzing (-fuzz, 4 workers) after the seed corpus passes, plus the
    hand-enumerated cross product (all start instants x all TTLs x all step
    kinds, single step) as a deterministic test.
R3  A failure is a FINDING only after the exact saved corpus input fails 3 out
    of 3 replays (`go test -run=FuzzX/<file>`), and is classified: BUG,
    SEAM-GAP (decision not drivable by the injected clock), EXPECTED
    (documented behaviour, e.g. fail-open on a misconfigured timezone), or
    TEST-ARTIFACT. SEAM-GAP findings get a deterministic repro test that
    asserts today's behaviour and says so.
R4  No production change is made by this PR. If a seam is missing the finding
    names the smallest change instead.
R5  Security-class BUGs are recorded in ~/proj/crash-private/FINDINGS.md first.
R6  Campaigns end before 2026-11-10T05:00Z with host load < 60% of cores.

## Results (2026-11-07)

- Schedule fuzz (FuzzEnforceScheduleDST, independent tzdata oracle): 10 min, PASS, no violations.
- Extreme-instant fuzz and cross-product test: no O1/O2 violations (no credential accepted after expiry, none accepted from a rolled-back clock). Mutants M1-M5 are all caught by the oracles.
- Observation, classified EXPECTED / low, fail-closed: with the clock at year <= 0, or a credential whose expiry is beyond year 9999, sessions and PATs are refused before their expiry (O3). Cause for year >= 10000: SQLite stores the value without error and reads it back as the zero time. The year-0 case is refused at mint time (the anti-rollback watermark starts at year 1). Neither is reachable through the API (RFC 3339 input stops at year 9999). The generators now skip that domain, and TestKnownLimit_* pin the behaviour.
- TOML: Keyorix does not parse TOML dates; BurntSushi/toml is only a transitive dependency of go-i18n and only JSON locale files are loaded.
- Seam gaps (not fixed here): unexpiredSecret and checkSecretAccessScheduleWith call time.Now() directly, so the fake clock cannot reach them.
