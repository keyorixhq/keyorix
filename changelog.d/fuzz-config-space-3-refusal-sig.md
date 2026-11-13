### Testing
- **configspace fuzzer: refusal-unnamed findings are keyed by the refusal, not the
  options.** The in-process and process-stage "refusal does not name the offending
  option" (I2c) findings now dedupe on a masked signature of the refusal text (numbers,
  paths, line numbers and quoted values stripped) instead of the case's first three
  option ids. The old key collapsed unrelated `pair-all` refusals into one entry and let
  minimisation drift between causes; the new key ties each finding to its cause so two
  different refusals can never share a key. Model conflict C20 also now matches a blank
  `storage.type` (mapped to `local` at boot), closing a stale false "unnamed refusal".
  `known.tsv` rows migrated accordingly (harness only, no production change).
