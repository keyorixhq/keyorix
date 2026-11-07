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
either: it was found in under a minute in only 2 of 6 runs, but in 5 of 6 within 3 minutes.

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
