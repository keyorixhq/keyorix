# Pre-registration: verifier bit-flip mutation (B2)

Written 2026-11-06, before any campaign run. Do not edit after the first run;
append dated amendments below the line instead.

## Question

For every integrity/authenticity verifier in Keyorix, given a valid artifact,
does any single-bit flip, truncation, extension, reorder, duplication, byte
deletion or byte insertion produce an accept of an artifact whose meaning
differs from the original, a panic, or a timing-class surprise?

Verifiers in scope (each is a registered Target in this package): backup
manifest HMAC; audit checkpoint signature + high-water string; audit seal
record MAC; audit key-transition MAC; audit retention anchor (v1, v2);
external anchor bundle; AEAD envelope (EncryptedData serialisation, AAD and
chunked); post-quantum wrap envelope; recovery key hash; evidence signature;
license (pkg/licenseverify); session/PAT/machine/setup token parsers where a
pure verifier exists; JWT verify path where reachable without a server. Targets
that need a running server (token validation against the DB) are exercised via
the pure parse/compare function only and listed as such.

## Mutation set

1. every single bit flipped (all bits if len*8 <= 65536, else the first 512
   bytes, last 512 bytes and a seeded uniform sample up to 65536 flips);
2. truncation to every prefix length (sampled the same way);
3. extension: +1 byte (0x00, 0xff, '\n', ' '), + the artifact appended to
   itself, + 64 random bytes (seeded);
4. reorder: swap every pair of adjacent 8-byte blocks (sampled), reverse the
   artifact, swap two halves, and for delimiter-structured artifacts swap
   fields;
5. delete each single byte; insert one byte (0x00) at each offset (sampled);
6. duplicate a block.

## Verdicts

- REJECT: verifier returns false/error. Good.
- ACCEPT-EQUIVALENT: verifier accepts AND the target's Canon(mutated) ==
  Canon(original) (semantic content identical, e.g. JSON whitespace, hex-case
  where the verifier is documented case-insensitive). Counted and listed,
  never a finding by itself; any class with >0 members is reviewed once and
  documented.
- ACCEPT-DIFFERENT: verifier accepts and Canon differs. CANDIDATE FINDING.
- PANIC: any panic. CANDIDATE FINDING.
- TIMING: see below. CANDIDATE FINDING only if it reproduces 3 times.

## Timing rule

Each reject is timed as the minimum of 5 calls (ns). A timing-class surprise
is (a) a reject whose min time exceeds 20x the median reject time of the
whole target and at least 50 microseconds above it, or (b) for MAC/signature
byte-position flips, the mean reject time of flips in the first quarter of
the MAC field differing from the last quarter by more than 1.5x after a
robust (trimmed) mean, on a target whose compare is claimed constant-time.
(b) is reported as information when it does not reproduce 3 times across
independent processes. Local machine noise is expected; a single outlier is
not a finding.

## What counts as a finding (confirmed)

An ACCEPT-DIFFERENT, PANIC or reproduced TIMING candidate that reproduces on
3 consecutive runs, classified as `real` / `expected-equivalent` /
`harness-bug`. Only `real` is a finding.

## What counts as negative

Zero confirmed real findings AND the planted-defect self-test passes: the
harness must flag every one of these planted defective verifiers: ignores the
last byte of the MAC; compares only a 16-byte prefix; accepts any input of
length 0; panics on a truncated input; early-exit (variable-time) compare
that is measurably slower for a longer matching prefix. If any plant is missed
the run is INVALID.

## Budget

Deterministic: all mutations above, per target, seeds 1..3. A few minutes
locally. No fuzz time needed; an optional Go-native fuzz target wrapping
mutation chains runs 30 min locally.

## Prior art (so this is not credited with what it did not do)

internal/auditverify/tamper_exhaustive_test.go flips every byte of audit
columns inside a live DB and asserts verdict != VALID; internal/backupfmt has
manifest_sign_test exhaustive tamper. This package flips every BIT of the
pure artifact encodings, adds truncate/extend/reorder, panic and timing
checks, and covers verifiers that had no exhaustive test.
