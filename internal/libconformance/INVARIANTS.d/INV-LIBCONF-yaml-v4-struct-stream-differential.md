- **INV-LIBCONF-yaml-v4-struct-stream-differential** The three DF3 companion
  targets in `yaml_v4_struct_stream_fuzz_test.go` must fail on any v3/v4
  divergence they surface UNLESS it is a downstream manifestation of an
  already-tolerated single-doc class (`yamlV4ExpectedDiff`) or a listed
  companion-specific class, between `go.yaml.in/yaml/v3` v3.0.5 and
  `go.yaml.in/yaml/v4` v4.0.0 on the same bytes:
  - `FuzzYAMLV4StructDifferential` (S1) — decodes into the real
    `internal/config.Config` family (the server's live strict-load target) and a
    synthetic struct, lenient (v3/v4 `Unmarshal`) and strict (v3
    `KnownFields(true)` vs v4 `WithKnownFields()`). A typed split where the
    `any`-path AGREED is a NEW typing-only divergence and fails
    (`structSplitVerdict`); a typed split tied to a tolerated `any`-path class is
    excused. Tolerated: `int: ! 00` rejects under v4 (keeps `"00"`) but resolves to
    int `0` under v3 — the D12 class made visible by typing. Strict mode tolerates
    `v4-strict-rejects:empty-doc` (`isV4StrictEmptyDocSplit`): v4's one-shot strict
    `Load` rejects an empty stream (`no documents in stream`) where v3's strict
    `Decoder` returns `io.EOF` and `Config.Load` treats that as all-default.
  - `FuzzYAMLV4MultiDocDifferential` (S3) — decodes EVERY document of a `---`
    stream (v3 `Decoder` loop vs v4 `Loader` loop) and compares the sequence. A
    differing document COUNT is `multidoc:count-mismatch` (NOT tolerated → a
    finding); per-document value splits reuse `classifyYAMLV4ValueSplit`.
  - `FuzzYAMLV4RoundTrip` (S2) — per library, `decode→encode→decode` must be a
    fixed point (re-decode canonicalises to the first decode). Tolerance table
    `yamlV4RoundTripExpectedDiff` is EMPTY on purpose.
  Why: DF3 (df2 leftovers 1–3) — the DF2 `any`-path oracle explicitly did not
  cover struct decoding (S1), round-trip (S2) or multi-document streams (S3); a
  config decoded into a typed struct can diverge where the `any` decode does not
  (confirmed: `int: ! 00`). `internal/config` has no custom `UnmarshalYAML`, so a
  struct oracle over it is not confounded by a `*yaml.Node`-bound unmarshaler.
  Guard: the three targets plus their seed corpora and
  `TestYAMLV4StructStreamRedGreen` (each oracle shown red on a planted divergence
  and green on a benign/tolerated input; `structSplitVerdict`,
  `isV4StrictEmptyDocSplit` and the count-mismatch gate each proven both
  directions). See `EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md` (D12, D13,
  companion-oracles section) and the DF3 report
  (`/mnt/data/wave4/out/df3-REPORT.md`).
