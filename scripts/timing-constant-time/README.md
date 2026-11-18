# timing-constant-time (NH1 / K12)

A **manual, one-off** calibrated timing-measurement tool. **It is not a test and must never
run in CI.** It empirically probes the constant-time behaviour of Keyorix's secret-comparison
leaf primitives with a [dudect](https://github.com/oreparaz/dudect)-style statistic
(Reparaz, Balasch & Yarom, *"Dude, is my code constant time?"*, DATE 2017).

## Why it is not a CI test

- It is slow (hundreds of thousands of measurements per site; the bcrypt site is minutes).
- Its verdicts are **host-dependent and noisy**: this runs on a shared, thermally-throttled
  box, and a single run's t-statistic is not trustworthy. A real finding requires the operator
  to run it **three separate times** and see a large |t| in **all three**.
- A green run proves nothing permanent (the measurement is a snapshot, not an invariant). The
  machine-checked guarantee that these sites use constant-time primitives lives elsewhere (the
  comparisons call `crypto/subtle.ConstantTimeCompare`, `crypto/hmac.Equal`, or
  `bcrypt.CompareHashAndPassword`, all constant-time w.r.t. content by construction). This tool
  is a calibration check on top of that, not a substitute for it.

## What it measures

For each site it measures the **exact leaf comparison** the production code performs, under two
interleaved input classes (dudect's two-class test):

- **class A — equal-prefix**: the presented value equals the secret except for its last byte,
  so it shares the longest possible common prefix. A byte-by-byte short-circuiting comparator
  spends the *most* time here.
- **class B — random**: independent random bytes of the *same* length, differing near the front
  on average. A short-circuiting comparator returns *early* here.

Both classes use equal length, so the (known, accepted) length short-circuit of
`ConstantTimeCompare` is held fixed and only **content-dependent** timing is tested. The
statistic is **Welch's two-sample t** on the cropped per-batch timing samples.

Verdict:

| \|t\|        | meaning                                                              |
|--------------|---------------------------------------------------------------------|
| `< 4.5`      | ok — no content-dependent timing detected                           |
| `4.5 – 10`   | borderline — almost always host noise; re-run                       |
| `>= 10`      | potential leak — **a finding only if stable across 3 separate runs**|

## Running

```sh
cd scripts/timing-constant-time
go build -o /tmp/ctt .
# pin to an idle core and lower priority; repeat THREE times:
taskset -c 2 env GOMAXPROCS=1 nice -n 19 /tmp/ctt -n 300000
taskset -c 2 env GOMAXPROCS=1 nice -n 19 /tmp/ctt -n 300000
taskset -c 2 env GOMAXPROCS=1 nice -n 19 /tmp/ctt -n 300000
```

Flags: `-n` (measurements per site, K12 minimum 200000), `-batch` (comparisons per timed batch,
raises the per-comparison signal over the ~20–40 ns Go monotonic-clock overhead), `-crop`
(drop batch times above this percentile of the combined sample — the documented outlier rule),
`-warmup`, `-bcrypt-n`, `-bcrypt-cost`, `-site` (measure one site), `-runs`.

## Deviations and scope (read before trusting the table)

- **bcrypt is measured at a reduced count.** `bcrypt.CompareHashAndPassword` at the production
  cost 12 takes ~230 ms per call on this host, so the K12 minimum of 200 000 measurements would
  take ~13 hours. `-bcrypt-n` defaults to 4000 and should be set to a few hundred for a quick
  pass. This is an explicit deviation from the 200k rule. It is acceptable because bcrypt's
  constant-timeness w.r.t. the password is **structural**, not statistical: it hashes the full
  password with the salt+cost and compares fixed-width digests, so classes A and B drive the
  identical code path. The reduced count still catches a gross regression; it is under-powered
  for a subtle one. Listed as a LEFTOVER in the report.
- **PAT and machine-identity tokens are not measured.** They are verified by SHA-256 hashing
  the presented token and looking it up by hash in the database (`GetPersonalAccessTokenByHash`,
  `GetMachineIdentityCredentialByHash`), never by a byte comparison of the raw secret, so there
  is no raw-token comparison to time.
- **Webhook signing is outbound only.** Keyorix signs the notifications it sends; there is no
  inbound webhook-signature *verification* path, so there is no attacker-controlled comparison
  to time.
- **The tool measures the primitive, not the live request path.** It replicates the exact leaf
  comparison (same stdlib/x function, representative length) in isolation. It does **not**
  exercise the surrounding handler, DB lookup, cache, or network, and therefore says nothing
  about timing channels *above* the comparison (e.g. an early `len==0` return, a DB lookup that
  differs by whether a token row exists, or a user-enumeration oracle in an outer branch). Those
  are out of scope for a leaf-comparison probe.
- **A green result is a snapshot**, valid for this binary, this host, this moment. It is not an
  invariant and does not belong in CI.
