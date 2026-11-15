### Testing
- **Swarm testing and typed-error oracles for the stateful OpenAPI fuzzer.**
  `FuzzOpenAPIStateful` now decodes a per-input *feature subset* (which operations, principals
  and resource kinds are enabled) from the corpus bytes, so a short sequence concentrates on a
  rare slice of the 307-operation surface instead of scattering uniformly; all-features stays
  reachable so no coverage is lost (`KEYORIX_OSF_NOSWARM=1` forces the plain generator, and
  `TestOpenAPISwarmReachProfile` measures the depth/absence-region gains at equal budget). Two
  new always-on oracles were added, each with a deterministic repo-wide census proving test:
  (6) a typed-error mapper — every `>=400` body is leak-free (no stack frame, internal path,
  SQL text or secret) and carries the documented `{success,error,message,code}` envelope
  (`TestOSFErrorMapperCensus`); (7) denial existence-independence — a zero-authority actor's
  denial status for a single-id GET/DELETE is the same whether the target exists or not, so it
  cannot be used as an existence oracle (`TestOSFDenialExistenceCensus`). Both oracles are
  green across all 309 enumerated operations today; both were red-proofed against planted
  defects. Guarded by `server/http/INVARIANTS.d/INV-HTTP-openapi-error-typed-and-leakfree.md`
  and `INV-HTTP-denial-status-existence-independent.md`.
