### Testing
- **Bounded-work super-linear fuzz oracle (`internal/fuzzutil/boundedwork`).** A
  fuzz oracle that measures the *shape* of a parser's time and memory cost across
  scaled variants of one input (factors 1,2,4,8) and fails on clearly super-linear
  (quadratic-or-worse) growth — the common real defect class that never-panic and
  absolute-ceiling harnesses miss. Fit over the asymptotic tail; the memory arm
  (`runtime.MemStats.TotalAlloc`) red-proofs deterministically. Guards in
  `INVARIANTS.d`; calibrated against the real yaml.v3 duplicate-key quadratic.
- **Ecosystem bounded-work generator (`scripts/fuzzing/bwgen`).** A `go/types`
  scan (offline) that finds decoder/parser/validator functions
  (`func([]byte|string|io.Reader)(T,error)` and `Unmarshal`-style) in the module
  cache and emits bounded-work + Marshal/Unmarshal round-trip fuzz targets. A BW1
  sweep of ~23 libraries (86 function targets) found a 0/78 false-positive rate;
  the committed green subset (`internal/boundedworksweep`: `encoding/json`,
  `go.yaml.in/yaml/v2`) are permanent linear-growth regression guards with
  `targets.d` entries.

### Internal
- **BW1 finding: yaml.v3-family duplicate-key quadratic (library defect).** Both
  offline yaml.v3 forks (`gopkg.in/yaml.v3` v3.0.1, `go.yaml.in/yaml/v3` v3.0.5,
  and the `oasdiff/yaml*` wrappers) decode a mapping of N duplicate keys in
  O(N²) time and memory (~4.19× per input-doubling; 20 KB → ~4.2 s, ~1.6 GB);
  `go.yaml.in/yaml/v2` is linear. No attacker-reachable Keyorix server path
  decodes untrusted yaml (all yaml.v3 use is operator/CLI config), so this is
  hardening, not a server vulnerability. See the BW1 report for the reproducer.
