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
  - **D14 `v4-strict-rejects:nonintegral-float-into-int`** — `int: 0.1` is silently coerced by
    v3 (truncating `0.1`→ int `0`, a data-loss footgun) but **rejected by v4**; integral floats
    agree. Found by the struct fuzzer; invisible to the `any`-path.
  - Surfaced via the typed path and tolerated via D12: `int: ! 00` is accepted by v3 (int `0`)
    but **rejected by v4** (cannot construct the kept string `"00"` into an `int` field),
    invisible to the `any`-path oracle. All forward-looking (v4 has no live Keyorix caller).
    Enforced by `INV-LIBCONF-yaml-v4-struct-stream-differential`.
  - The fuzz run also drained a further any-path tail (all red/green proven, documented): **D15**
    `v3-rejects:flow-seq-tagged-empty` (`[!x]`), **D16** `v3-rejects:flow-node-content` (`[: 1]`),
    **D17** `nonspecific-tag-structural` (the `!`-tag divergence in a KEY, `! : 00`), **D18**
    `anchor-name-colon-boundary` (a `:` inside an anchor name, `&a:b`: v3 `":b"` / v4 nil), and a
    round-trip footgun **`roundtrip:negzero-float-to-int`** (`-.000`: v3 float `-0.0`→`-0`→ int `0`,
    non-idempotent — D10 across a round-trip). A reflection-walker key-type panic
    (`map[string]any` vs `map[any]any`) was fixed with a logical-key lookup.
