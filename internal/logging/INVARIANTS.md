# logging invariants

`internal/logging` gives the server one log shape and a redaction scrubber.
Redaction is **defence in depth, not the primary control** (the primary control
is that call sites never pass a secret to a log function). The scrubber catches
secrets that have a recognisable FORM; it cannot catch a bare high-entropy value
with no shape, by design (`redact.go` says so).

Format: `INV-LOG-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

Every invariant is a one-per-file fragment in `INVARIANTS.d/INV-LOG-<slug>.md`
(never defined here): `INV-LOG-event-redacts-both-formats` (the Event path
redacts recognisable secrets in both text and json mode),
`INV-LOG-redact-idempotent` (`Redact` is idempotent) and
`INV-LOG-injection-no-forge` (injection via the sanitised positions cannot forge
a record/line). Read the fragments for the full statement and the guard test.

## Known defence-in-depth boundaries (NOT invariants — do not rely on them)

These are documented gaps, each pinned by a characterization test that turns red
if the gap closes (so the boundary stays visible), surfaced by LG1:

- A **raw `log.Print`** (not `Event`) is Redacted only in **json** mode
  (`jsonWriter`); in **text** mode (the default) `Setup` leaves the standard
  logger untouched, so raw `log.*` output is NOT redacted. Pinned by
  `TestLG1_RawTextLogNotRedacted_Characterization`.
- Even in json mode, `jsonWriter` Redacts each **physical line** independently,
  so a **multi-line PEM** logged as a raw line leaks its key body (the middle
  line has no PEM markers of its own). The same value via `Event` is fully
  redacted. Pinned by `TestLG1_JSONRawLogSplitsMultilinePEM_Characterization`.
- In **text** mode the **message** and the kv **key** are written raw (only kv
  values and `SanitizeID` fields are newline-stripped). Keys/messages are
  developer constants by contract; an attacker-controlled one injects a line.
  Pinned by `TestLG1_TextRawPositions_Characterization`.
