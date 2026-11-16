### Changed
- **YAML parsing moves from the archived `gopkg.in/yaml.v3` to `go.yaml.in/yaml/v4` (v4.0.0).**
  `gopkg.in/yaml.v3` has been archived upstream and receives no fixes; v3 of the maintained
  fork is security-fixes only, and active development is on v4. The classic `Unmarshal`,
  `Marshal`, `NewDecoder` and `NewEncoder` entry points keep their v3-compatible settings,
  so config, import and export parsing behave as before. The guard tests that forbid the
  YAML library in `internal/core` and inventory its egress now name the v4 import path.
  One operator-visible difference: a config type error now reads `yaml: construct errors:
  line N: cannot construct !!str ... into bool` (was `yaml: unmarshal errors:` / `cannot
  unmarshal`); the `unknown key "X" under <section>` rewrite is unchanged.
  Duplicate keys in a mapping still cost quadratic time and memory in v4 (reported upstream
  as yaml/go-yaml#510).
