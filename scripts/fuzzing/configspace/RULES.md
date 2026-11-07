# Config-space fuzzer: pre-registered rules

Status: registered BEFORE the first matrix run. Changing a rule after results exist
requires a new dated amendment at the bottom of this file, never an in-place edit.

Scope: the startup configuration surface of `keyorix-server`: the YAML file
(`KEYORIX_CONFIG_PATH`, default `keyorix.yaml`), the process flags
(`--passphrase-fd`, `--passphrase-file`, `--passphrase-stdin`), the `KEYORIX_*`
environment variables that feed secrets (`<NAME>` and `<NAME>_FILE`), deprecated key
aliases, built-in defaults, and the build profile (default or `airgap`).

Method: a covering array (all-pairs) over the option values in `model.yaml`
(valid, boundary, empty, absent, and, in single-fault rows only, invalid), plus seeded
random multi-option mutation rows, plus a Go native fuzz target on the parse and
validate function. All-pairs and not random is deliberate: earlier harnesses showed
that random combination sampling misses the two-option interactions this class of bug
lives in.

## Verdict vocabulary

Every candidate is classified exactly once, after minimisation and at least 3 replays:

- `bug`: Keyorix behaviour that violates a rule below and is not documented.
- `by-design`: violates the letter of a rule but is documented behaviour (docs or
  ADR cited); recorded as a policy note, not a bug.
- `artifact`: caused by the harness, the sandbox, or an environment limit.
- `flaky`: did not reproduce 3 of 3.

## Severities

- S1: the server accepts the configuration and runs in an insecure posture with no
  refusal and no warning, or a secret value is exposed.
- S2: a security-relevant setting is accepted but not applied as written (ignored,
  weakened, or overridden by a weaker source), or an insecure posture is reached only
  with a warning and with no explicit weakening key set.
- S3: crash, hang, or partial start; or an invalid value is accepted/ignored with no
  security effect; or a refusal that does not name the offending option.
- S4: wording, ordering, or documentation drift; policy notes.

## Invariants

### I1 No crash, no hang (S3, S2 when the crash is after a listener opened)

`config.Load`, `Config.Validate`, `keyorix-server admin validate`, `admin diagnose`,
and the plain `keyorix-server` start never panic, never exit by a signal other than
those sent by the harness, and never fail to exit or listen within 30 s.

### I2 Invalid and contradictory input is refused cleanly (S2 / S3, see below)

(a) Every value the model classifies `invalid` is refused. Refusal means: `Load` or
`Validate` returns an error in-process, and the process exits non-zero.
(b) Every contradiction listed under `conflicts:` in the model is refused.
(c) The message names the offending option (its dotted key, or for env/flags the
variable or flag name).
(d) No partial start: after a refusal no listener accepts connections on the
configured ports, and the process has exited.
(e) An invalid value that is silently replaced by a default is a violation. S2 when the
default is weaker than what the operator evidently asked for or the option is in the
security-relevant set; S3 otherwise. If the code comment or docs document the
fallback it is recorded `by-design` and listed as a policy note.

### I3 No silent insecure posture (S1 / S2)

"Insecure" is defined independently of the code's own registry, in `model.yaml`
under `posture:`; the first set of predicates is:

- P01 a listener is enabled with TLS off and the bind address is not loopback
- P02 a listener is enabled with TLS off (any bind address)
- P03 `/metrics` is reachable without a token on an enabled listener
- P04 storage encryption is disabled
- P05 login lockout is disabled
- P06 rate limiting is disabled on an enabled listener
- P07 MFA is not required
- P08 the file-permission/startup validation is skipped or softened
- P09 session lifetime is unbounded (no absolute ceiling)
- P10 trusted proxies include a catch-all range
- P11 swagger or gRPC reflection is enabled
- P12 the SIEM transport is plaintext or certificate verification is skipped
- P13 keyless admin recovery is enabled
- P14 a weaker key-provider fallback is allowed
- P15 audit durability is relaxed, audit reads are skipped, or audit checkpoints are
  disabled
- P16 CORS allows a non-loopback http origin
- P17 the database connection is not verified (sslmode disable/allow/prefer) with a
  non-loopback host
- P18 the TLS floor is below 1.2 or a weak cipher is permitted

Requirement for each predicate that holds on an accepted configuration:
(a) the weakening must be reachable only through an explicit key (S2 if a default plus
an unrelated option reaches it; S1 if it is reached with no weakening key at all and
no log line);
(b) the plain start logs a line beginning `WARNING` that names the condition on every
start (S1 if absent, checked at process level);
(c) where the code refuses the condition when a sibling option is set (for example
`security.require_transport_tls`), the refusal fires.

Fidelity corollary (S2): a security-positive setting written explicitly in the file
(TLS enabled, MFA required, rate limit enabled, a metrics token set, lockout not
disabled, encryption enabled, ciphers restricted) must be present in the effective
configuration after `Load` or the configuration must be refused. Documented
normalisations are listed in `model.yaml` under `normalisations:` and nothing else.

A warn-only design (condition logged, no opt-in key, no refusal) satisfies (b) but not
(a); it is recorded `by-design` with the doc reference and reported as a policy note.

### I4 No secret in any output (S1)

Each secret-bearing option and env var is set to a unique canary string. The canary
must not appear in: error text from `Load`/`Validate`, `fmt` of the loaded config,
the process stdout/stderr and log files for a start or a refusal, `admin validate`,
`admin validate --posture`, `admin diagnose`, unauthenticated `/health`,
`/api/v1/system/info`, and `/metrics` without a token. A canary in a file written by
the harness itself (the config file) is not a leak.

### I5 Precedence and aliases are consistent and never weaken (S2)

- `<NAME>` and `<NAME>_FILE` both set: refused, naming both (docs/CONFIGURATION.md,
  "Secrets from files").
- `<NAME>_FILE` unusable: refused, with no fallback to `<NAME>` or the YAML value.
- `<NAME>` set and the YAML value set: the effective value is `<NAME>`.
- A DSN carrying a password plus a password source: refused.
- A deprecated alias key behaves exactly as the key it was renamed to (same effective
  configuration, same in-effect insecure settings), and a conflict between alias and new
  key is refused or the stricter value wins; never the weaker.
- An explicit YAML value beats a built-in default.

### I6 Start, health, graceful shutdown (S3)

For every accepted startable configuration in the sample: the process starts within
30 s, logs a listening line for each enabled listener, answers `/health` with 200 on
every enabled HTTP listener (TLS or not, as configured), exits 0 within 15 s of
SIGTERM and logs the graceful-shutdown line. Rows whose environment cannot start
(PostgreSQL, KMS, TPM, external IdP) are excluded and recorded as `not-startable`.

## Oracle controls

The self-test (`planted/`) applies each patch to a scratch copy of the tree, builds it,
and requires that the harness reports the planted defect under the named invariant. The
unpatched build is the control and must report nothing for the planted ids. A run is
only valid if the self-test passed on the same commit.

## Amendments

2026-11-07 (made after an exploratory first run; the rules' intent is unchanged,
only predicate precision):

- P06: the predicate also covers a degenerate rate-limit setting on an enabled
  listener (details withheld from this public file).
- P12: only a non-loopback plaintext SIEM endpoint, or a skipped certificate
  verification, counts as insecure. Loopback endpoints are exempt.
- I2a: command-line and master-passphrase parameters are judged only by the
  process stage; the in-process stage does not apply I2a to them.
- Deferral: an "invalid value accepted" result from the in-process stage is
  dropped when the same option is refused at boot in any case (key level).


2026-11-07 (second amendment, before the final run):

- Process stage binds loopback only. Values that bind every interface (host
  0.0.0.0 or ::) are checked by Load and Validate only and are never started.
  Consequence: the P02 warning check (non-loopback, no TLS) cannot be exercised
  at process level, and the planted warning-suppression defect targets the
  login-lockout warning instead.
- Process stage adds, for each inline-secret option, one case with the file-based
  twin removed, so the inline secret is actually in effect when I4 is checked.
