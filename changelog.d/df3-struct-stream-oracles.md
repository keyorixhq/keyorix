### Testing
- **Extended the YAML v3→v4 differential (`internal/libconformance`, DF3) with struct-decode,
  multi-document-stream and round-trip oracles.** `FuzzYAMLV4StructDifferential` decodes the
  same bytes into the real `internal/config.Config` family and a synthetic struct (lenient and
  strict `KnownFields`/`WithKnownFields`); `FuzzYAMLV4MultiDocDifferential` compares every
  document of a `---` stream; `FuzzYAMLV4RoundTrip` asserts per-library `decode→encode→decode`
  idempotence. Each ties typed/stream divergences back to the single-doc class table, so a
  typed split where the `any`-path agreed is a finding. New tolerated classes, all red/green
  proven (`TestYAMLV4StructStreamRedGreen`) and documented
  (`EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md`):
  - **D12 `nonspecific-tag-nonempty-scalar`** — generalises the DF2 D1 empty-scalar class to
    non-empty scalars: `! 00`→ v3 int `0` / v4 `"00"`, `! true`→ v3 bool / v4 `"true"`, etc.
  - **D13 `v4-strict-rejects:empty-doc`** — v4's one-shot strict `Load` rejects an empty stream
    (`no documents in stream`) where v3's strict `Decoder` returns `io.EOF` and `Config.Load`
    treats it as a valid all-default config — a forward-looking config-loader migration gotcha.
  - Surfaced via the typed path and tolerated via D12: `int: ! 00` is accepted by v3 (int `0`)
    but **rejected by v4** (cannot construct the kept string `"00"` into an `int` field),
    invisible to the `any`-path oracle. All forward-looking (v4 has no live Keyorix caller).
    Enforced by `INV-LIBCONF-yaml-v4-struct-stream-differential`.
