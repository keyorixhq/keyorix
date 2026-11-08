# Authorization-decision novelty as fuzz feedback: pre-registered comparison

Status: written and committed BEFORE any comparison run. Results are appended
under "Results", never edited into this section. (2026-11-07)

## Question

Go native fuzzing keeps an input when it reaches a new code edge. For an
authorization harness the interesting novelty is a new DECISION: a principal
kind being allowed or denied an operation at a scope it was not seen at before.
Two different (actor, scope) pairs run the same code, so the plain-coverage
fuzzer treats the second as nothing new and may discard the input that found
it. Does feeding decision-tuple novelty to the fuzzer reach more decisions
sooner, and find a defect that hides behind a rare decision sooner?

## Tuple

(actor kind, verb, resource type, decision, scope), where
* a step tuple is: acting principal kind, one of the 8 step kinds
  (role.grant ... grant.expire's API steps; the two state steps have no
  decision), its resource type (role-grant, account, group-membership),
  consensus decision of the transports (allow / deny / other), scope (A, B,
  global);
* a probe tuple is: probed principal kind, secrets.read, secret-value, consensus
  decision of the legs, scope (project A or B).
624 slots (576 step, 48 probe); most are unreachable (a no-role actor cannot be
allowed). Defined in `seq_novelty_test.go`.

## Mechanism (what "feeds the fuzzer")

`novEdge(id)` is a generated switch with one case per tuple, each case a
distinct basic block. Under `go test -fuzz` each block is an instrumented
coverage edge, so executing a tuple for the first time is a new edge and the
engine keeps the input and mutates it further. This needs no change to the Go
engine and no custom corpus manager. The recorder (which tuples were seen, when)
is identical in both arms; the arms differ in one environment variable:

* arm P (plain coverage): `AUTHZNOV_FEED` unset, `novEdge` never called;
* arm T (tuple feedback): `AUTHZNOV_FEED=1`, `novEdge` called for every tuple
  executed.

The same test binary, built once with `go test -c -fuzz`, is used for both arms,
so instrumentation overhead is identical.

## Design

* Target: `FuzzAuthzSeqNov` (same body and triage as `FuzzAuthzSeq`, plus the
  recorder and an optional planted defect). Seeds: its two `f.Add` seeds, same in
  both arms; the fuzz cache directory is empty at the start of every run.
* Go's mutator is not seedable, so "same seeds" means the same seed corpus and an
  empty cache; run-to-run variance is handled by >= 3 repeats per arm and
  reporting every run, not only the mean.
* Budget: `-test.fuzztime=5m -test.parallel=2`, `GOMAXPROCS=2`, nice 15, on the
  Mac (shared machine). 3 repeats per arm per condition; arms interleaved (P1 T1
  P2 T2 P3 T3) so machine load drifts across both.
* Conditions:
  1. CLEAN (no plant): measures tuple reach.
  2. RARE plant: `AUTHZNOV_PLANT=rare`, REST wrongly denies a custom-role
     principal that is allowed to read at scope A (probe tuple custom-role,
     secrets.read, allow, A). In the census (100 random sequences, seeds
     9,000,000+, not used by any comparison) 1 of 100 sequences reached it.
     Chosen from the census as one of the rarest reachable tuples BEFORE any
     comparison run.
  3. COMMON plant (control for the metric): `AUTHZNOV_PLANT=common`, REST
     answers a server error when the global admin is allowed to grant a role at
     scope A (step tuple global-admin, role.grant, allow, A; 4 of 100 sequences).
     Both arms should find it fast; the claim is only that T is not worse.
* The planted defects are in the harness (seqFault), never in production code.
  The unplanted target must stay clean (condition 1 is also the clean control:
  a failure there is a harness finding, not a metric result).

## Measures

From the recorder log (`T` lines: first sighting of a tuple in a process, with
timestamp, pid and that process's exec count; `E` lines: exec heartbeats):

* M1 reach: number of distinct tuples seen, restricted to the 103 tuples of the
  census (reached tuples outside the census are reported separately), after
  100, 200, 300 and 500 total executions (sum over workers, aligned by time),
  and at the end of the run.
* M2 time-to-all: time until all 103 census tuples are seen; if not reached in
  5 minutes, "not reached", plus time to 90 of 103 (about 87%).
* M3 time-to-find (conditions 2 and 3): wall-clock time from the start of the
  fuzz run to the first `F` line / test failure, capped at 5 minutes
  (censored runs are counted as "not found in 5 min").
* Executions per second per arm (the tuple blocks cost something).

## Success rule (decided now)

The metric is credited ONLY IF both hold:
1. In condition 2 (RARE), arm T finds the planted defect in a strictly smaller
   median time than arm P over the 3 repeats, with at least as many found-runs
   (a run not found in 5 minutes counts as 5 minutes), AND
2. In condition 1 (CLEAN), arm T's median M1 at 300 executions and at the end
   of the run is not lower than arm P's, and T is higher in at least 2 of the 3
   paired repeats at 300 executions.

If (1) fails the claim "the metric finds rare-decision defects faster" is
WITHDRAWN. If (1) holds and (2) fails, the report says the metric found the
defect but did not widen decision reach. If the common-plant control (3) shows
T more than 2x slower than P in median, the metric is reported as harmful.
Three repeats is a small sample: a pass is "consistent with", not proof, and
the report says so. A null or negative result is a valid outcome and is
reported as such.

## Out of scope

No change to the engine, no custom corpus manager (the edge-switch needs
none). The deterministic sweep (`TestSeqSweep`) is not changed.

## Results (2026-11-07, Mac, GOMAXPROCS=2, `-test.parallel=2`, nice 15, 5 min per run)

Raw logs are kept outside the repository. 18 runs, arms interleaved. The Mac was
shared with other builders (load average 8 to 100 during the runs), which moved
the executions per run between 94 and 666; the registered axis for reach is
executions, not seconds, for that reason. The binary was built once
(`go test -c -fuzz`).

### Condition 1, CLEAN: decision tuples reached (of the 103 census tuples)

| | after 100 execs | 200 | 300 | 500 | end of run (execs) |
|---|---|---|---|---|---|
| P repeat 1 | 30 | 32 | 37 | 38 | 38 (553) |
| P repeat 2 | 31 | 35 | 35 | 42 | 42 (552) |
| P repeat 3 | 31 | 40 | 44 | 47 | 47 (567) |
| T repeat 1 | 27 | 36 | 38 | n/a | 38 (311) |
| T repeat 2 | 29 | 34 | 37 | 40 | 42 (666) |
| T repeat 3 | 29 | 32 | 37 | 44 | 44 (500) |
| median P / T | 31 / 29 | 35 / 34 | 37 / 37 | 42 / 42 | 42 / 42 |

* M1: T is not ahead. At 300 executions T is higher in 2 of 3 pairs (38>37,
  37>35, 37<44) and the medians are equal, so success condition (2) holds, but
  only because nothing differs.
* M2 time-to-all: not reached in any run of either arm (best run 47 of 103).
  Time to 90 of 103: not reached.
* Tuples outside the census: 3 to 8 per run in both arms.
* Engine "new interesting" inputs at the end: P 6 to 7, T 7 to 8.
* Reference (not a comparison arm): `TestNovCensus`, plain random generation of
  100 sequences, reached all 103 tuples in about 4 minutes on the same machine.
  Go's native fuzzer, with or without tuple feedback, reached 30 to 31 tuples
  after 100 executions and about 40 after 500. For this state space the random
  generator of `TestSeqSweep` explores decisions far faster than the fuzz engine
  mutating short seeds.

### Condition 2, RARE plant (custom-role principal allowed to read at scope A)

Time to the first `F` line (the registered measure; it includes the harness's
own triage and shrink, equal in both arms):

| | repeat 1 | repeat 2 | repeat 3 | median | found within 5 min |
|---|---|---|---|---|---|
| P | 155 s | 27 s | 188 s | 155 s | 3 of 3 |
| T | 20 s | 78 s | not found (94 execs only: machine starved) | 78 s | 2 of 3 |

Secondary: the Go engine itself reported a failing input in 1 of 3 P runs and in
2 of 3 T runs; in the other P runs the target saw the defect (`F` line) but the
engine ended with PASS.

Registered rule (1) needs a strictly smaller median AND at least as many found
runs. The median is smaller (78 s against 155 s) but T found it in 2 runs and P
in 3, so the rule is NOT met. The claim "the metric finds a rare-decision defect
faster" is WITHDRAWN. The plant turned out not to be rare for the fuzzer
either: it was found in under a minute in only 2 of 6 runs, and in 5 of 6 within 5 minutes.

### Condition 3, COMMON plant (control)

P 29, 24, 11 s; T 26, 14, 10 s; all 6 found. The planted tuple is the first
seed's own step, so both arms find it while gathering the baseline coverage:
the control shows no harm and says nothing more.

### Reading

* No evidence that decision-tuple feedback helps in this harness. Reach is the
  same, the one apparent speed-up (median 78 s against 155 s) comes with a lost
  run and rests on 3 repeats under heavy machine load.
* Likely reason: plain coverage already separates allow from deny for each
  principal, because the product code takes different edges, so a tuple adds
  little that the engine did not already count. The fuzz engine's limit here is
  mutation of tiny seeds, not the feedback signal.
* What would change the conclusion: a quiet machine (the pve01 slot) with 10
  repeats, and a plant on a decision that does not change any code edge.
* The mechanism itself works (it adds one instrumented block per tuple) and costs
  nothing measurable; it stays opt-in (`AUTHZNOV_FEED=1`) and is not wired into
  any campaign.

## Amendment 1 (2026-11-08), written and committed BEFORE the 10-repeat run

The success rule above is NOT changed. The run is repeated on a quieter machine
with more repeats, and the only edits are the ones below. The 3-repeat results
above stay as they are.

* Machine and process model: pve01 (Intel i7-6700, 8 cores), not the Mac. Each
  run is one fuzz process with `-test.parallel=1` and `GOMAXPROCS=1`, nice 10,
  at most 6 runs in parallel (so about one core per run). The first round used
  `-test.parallel=2`, `GOMAXPROCS=2`. Executions per run therefore differ from
  the first round; reach stays measured on the executions axis as registered.
* Binary: built once from this branch (cross-built `GOOS=linux GOARCH=amd64`,
  `CGO_ENABLED=0`, `go test -c -fuzz`), the same binary for both arms.
* Repeats and cap: 10 independent runs per arm per condition (clean, rare,
  common), each with its own empty fuzz cache, 5 minutes per run in every
  condition (the first round used 3 minutes for the common plant; the registered
  cap is 5). Run order is interleaved by repeat (P then T for each repeat, the
  conditions in turn) and scheduled across the 6 slots.
* Counts of the rule, scaled from 3 to 10 repeats, mechanically:
  - rule (1): "strictly smaller median" and "at least as many found-runs" are
    unchanged (a run not found in 5 minutes counts as 5 minutes);
  - rule (2): "T not lower in median M1 at 300 executions and at the end of the
    run" is unchanged; "T higher in at least 2 of the 3 paired repeats at 300
    executions" becomes "T higher in at least 7 of the 10 paired repeats"
    (2/3 rounded up; repeat i of P is paired with repeat i of T; the pairing is
    nominal because the repeats are independent; ties count against T);
  - rule (3): "T more than 2x slower than P in median" is unchanged.
* Reporting: medians, min and max, found counts, every run. For the RARE
  time-to-find an exact two-sided permutation p-value is also printed as a
  description only; it does not enter the rule. No other test is run.
* Validity checks, decided now: (a) self-test: the planted defect must be found
  (an `F` line) in at least one arm of its condition, otherwise that condition
  is invalid; (b) the CLEAN condition (no plant) must produce no `F` line in
  either arm, otherwise it is a harness finding and is reported as such.
  A run that dies for infrastructure reasons (not a fuzz failure) is rerun with
  the same label and the rerun is reported.

## Results (10 repeats, 2026-11-08, pve01, Amendment 1)

60 runs, 10 per arm per condition, each with an empty cache, 5 minutes, 6 runs
in parallel (`-test.parallel=1`, `GOMAXPROCS=1`, nice 10), arms interleaved. One
binary (commit `bac73541e` sources). Package temperature peaked at 92 C, load
average about 5 to 6 during the runs. No run died for infrastructure reasons;
none was rerun. Raw logs are kept outside the repository. Throughput was about
260 executions per run (the Mac round had 94 to 666), so the registered
"after 300 executions" point was reached by only 2 of 10 runs per arm.

### Validity checks

* Self-test: the RARE plant was detected (an `F` line) in 4 of 10 P runs and
  5 of 10 T runs; the COMMON plant in 10 of 10 in each arm. Valid.
* CLEAN control: no `F` line in either arm (0 of 20). Silent, as required.

### Condition 2, RARE plant: time to the first `F` line (seconds; 300 = not found in 5 min)

| arm | runs | median | min / max | found |
|---|---|---|---|---|
| P | 300, 300, 15, 300, 88, 33, 300, 17, 300, 300 | 300 | 15 / 300 | 4 of 10 |
| T | 300, 219, 26, 30, 22, 300, 270, 300, 300, 300 | 285 | 22 / 300 | 5 of 10 |

Rule (1): T median 285 s is strictly smaller than P median 300 s, and T found 5
against 4, so rule (1) is met on its letter. Both medians sit at the censoring
cap or one step from it: the P median is the cap itself, and the T median is the
mean of the 5th and 6th ordered values (270 and 300). The difference is one
found run; an exact two-sided permutation p-value on the median difference is
1.00 (description only). The Go engine itself reported a failing input in 4 P
and 3 T runs. Secondary: in the 3-repeat round the plant was found in 5 of 6
runs; here in 9 of 20, so the plant is hard for both arms on one core.

### Condition 1, CLEAN: decision tuples reached (of the 103 census tuples)

| | median | min / max |
|---|---|---|
| P, after 100 execs | 29 | 26 / 42 |
| T, after 100 execs | 28 | 26 / 36 |
| P, after 200 execs | 33 (9 runs) | 29 / 44 |
| T, after 200 execs | 31 | 28 / 43 |
| P, end of run (median 261 execs) | 35 | 31 / 44 |
| T, end of run (median 267.5 execs) | 35 | 28 / 47 |

* Paired repeats (repeat i of P against repeat i of T), T higher / lower / tied:
  at 100 execs 3 / 6 / 1; at 200 execs 3 / 6 / 0 (9 pairs); at end of run
  5 / 5 / 0.
* At 300 executions only 2 P runs (33, 40) and 2 T runs (34, 35) have a value;
  only one repeat has a value in both arms (T 34 against P 40). The registered
  criterion "T higher in at least 7 of 10 paired repeats at 300 executions" is
  therefore not met (0 of 10; 1 evaluable pair, T lower). The medians at 300
  executions (P 36.5, T 34.5) rest on 2 runs each and mean little.
* M2 time-to-all and time to 90 of 103: not reached in any run of either arm
  (best run 47 of 103). Tuples outside the census: 2 to 7 per run in both arms.

### Condition 3, COMMON plant (control)

P median 4 s (4 to 5), T median 5 s (4 to 5); 10 of 10 found in each arm, on the
first seed execution. Ratio of medians T/P is 1.03, far from the 2x harm line.
The control is trivial by construction and says only that the feedback does no
harm here.

### Verdict by the registered rule

* Rule (1), RARE: met on its letter (285 s against 300 s; 5 against 4 found).
* Rule (2), CLEAN: not met. Median reach at the end of the run is equal (35 and
  35, so "not lower" holds), but the paired criterion fails (0 of 10 at 300
  executions, and 300 executions were mostly not reached), and at 100 and 200
  executions T is lower in 6 of 10 and 6 of 9 pairs.
* Both are required, so the metric is not credited. The control shows no harm.

### Is 10 repeats enough

No. The rare-plant result is borderline: it rests on a one-run difference in
found counts and a median that sits at the censoring cap; the permutation
p-value is 1.00. 4 of 10 against 5 of 10 cannot be told apart at this sample
size (a difference of that size would need on the order of hundreds of runs to
be detected). The clean-condition reach differences are within the spread
between repeats (end-of-run range 31 to 44 for P, 28 to 47 for T). The run
supports "no measurable effect of the feedback in this harness at this
budget", not "the feedback helps" and not a proof of harm. The earlier
conclusion that tuple feedback adds little over plain edge coverage here is
unchanged.
