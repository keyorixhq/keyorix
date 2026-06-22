# ADR-050: ML-based anomaly detection (Isolation Forest)

## Status

Accepted.

## Context

Keyorix already detects anomalous secret access (ADR-026): a per-secret statistical
detector (`internal/core/anomaly.go`) learns a 30-day baseline and emits `AnomalyAlert`
rows surfaced in the Anomaly Alerts UI and pushed to admins / SIEM when alerting is
enabled (ADR-026 + the NIS2 detection-&-response posture).

Those detectors are **single-signal rules**: off-hours by a fixed 22:00–06:00 clock
band, a never-before-seen IP, a never-before-seen user, and a read-volume spike. Each
fires on one binary condition, which leaves two real gaps:

- **Graduated rarity.** The `new_user` / `new_ip` rules are binary — an actor is
  "known" or "unknown". An identity that *is* in the baseline but is used only rarely
  (a human who touches a service-account secret a handful of times a month) never trips
  a rule, yet a sudden use of it is exactly the kind of event worth surfacing.
- **Multivariate combinations.** An access whose hour, source IP and actor are each
  individually unremarkable but *jointly* rare is invisible to any single rule.

The M3 roadmap (and the ENISA AI-feature narrative) calls for an ML anomaly detector.
This ADR records that decision and its scope.

## Decision

Add an opt-in **Isolation Forest** pass (Liu, Ting & Zhou, 2008) layered onto the
existing detector — it complements the rules, it does not replace them.

- **Algorithm.** A dependency-free, pure-Go Isolation Forest
  (`internal/core/isolation_forest.go`): an ensemble of randomly-grown binary trees on
  subsamples of the *normal* baseline. A point's average path length to isolation is
  its anomaly score `s = 2^(-E[h(x)]/c(ψ))` in (0,1); points isolated quickly (short
  paths) score high. Unsupervised — no labels, which we do not have.
- **Per-secret model.** Each detection pass, for each secret with at least 20 baseline
  accesses, a forest is trained on that secret's 30-day access history and used to
  score the last hour's accesses. Below the floor the pass abstains (too little to
  learn; the rules already cover sparse-history secrets).
- **Features (`internal/core/anomaly_ml.go`).** Four low, interpretable dimensions per
  access — hour-of-day as a cyclic `(sin, cos)` pair, the baseline occurrence count of
  the access's IP, and of its user. Hour is encoded on the unit circle so 23:00 and
  01:00 are adjacent and every hour is an *interior* point (an unused hour lands in an
  empty interior region the forest isolates well; a raw 0–23 integer would make an
  off-pattern hour an extrapolation point, which Isolation Forest separates poorly).
  The count features give the graduated-rarity signal the binary rules lack.
- **Alerts.** An access scoring above the threshold emits an `ml_outlier`
  `AnomalyAlert` carrying its score, accessor and IP. Severity is `high` at score ≥
  0.75, else `medium`. These flow through the same storage, list/filter, acknowledge,
  alerting and retention paths as every other alert — no new surface.
- **Determinism.** The model RNG is seeded (`math/rand`, config `seed`, default 1), so
  scoring is reproducible across restarts and testable. This RNG drives model sampling
  only; no security decision rides on it (it is not `crypto/rand`, by design).
- **Config-gated, default off.** `anomaly_alerts.ml` (`enabled`, `threshold`,
  `num_trees`, `sample_size`, `seed`). `ml.enabled` is independent of
  `anomaly_alerts.enabled`: the former gates whether the scan additionally runs the ML
  pass, the latter gates whether *any* detected anomaly is pushed out. The ML pass runs
  inside the existing single-replica-gated scheduler (ADR-039).

## Threshold choice

With this deliberately low-dimensional feature set, normal accesses cluster near 0.5
and the genuinely rare tail reaches ~0.65–0.8, so the default cutoff is **0.60** —
clearly above the 0.5 noise floor while still catching the rare tail. It is an operator
dial; raise it to reduce volume, lower it to widen the net. Empirically a brand-new
actor+IP (which the rules also catch) scores into the high band (~0.77), so the ML
score *corroborates* the rules rather than contradicting them, while a known-but-rare
actor at a normal hour (which no rule catches) scores ~0.67 — the headline value-add.

## Privacy & safety

Metadata only — like the rest of the anomaly subsystem the forest never sees a secret
value; its features are derived solely from access-log timestamps, actor names and IPs.
The pass is best-effort and isolated: a training/scoring failure for one secret is
skipped, never aborting the scan, and with the feature off the system behaves exactly
as before.

## Alternatives considered

- **More features / higher dimensionality (user-agent, action, day-of-week, inter-
  arrival time).** Deferred. The four chosen features are interpretable and already
  cover the two gaps; more dimensions dilute the signal in a low-data per-secret regime
  and make alerts harder to explain. Easy to extend later via `accessFeatures`.
- **A global (all-secrets) model instead of per-secret.** Rejected for now — "normal"
  is per-secret (a CI secret read thousands of times vs. a break-glass secret read
  twice), and a per-secret model needs no cross-secret feature normalisation.
- **An external ML service / Python sidecar.** Rejected — a pure-Go in-process forest
  keeps the single-binary deployment model, adds no dependency or attack surface, and
  is fast on this data volume.
- **Replacing the statistical rules.** Rejected — the rules are cheap, explainable and
  catch binary novelty deterministically; ML adds the rare/combination signal on top.

## Deferred follow-ups

- Richer features (user-agent / action / inter-arrival) behind `accessFeatures`.
- Score persisted on the alert row + a UI column / sort, and an explanation of *which*
  feature drove the score.
- Per-secret adaptive thresholds (contamination-based) instead of one global cutoff.
- Online / incremental model refresh rather than retrain-per-pass (only matters at much
  larger access volumes).
