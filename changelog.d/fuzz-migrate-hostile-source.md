### Testing
- **Hostile-source fuzzing for the `keyorix-migrate` tool and its `vault scan` health
  assessment.** The record-and-mutate hostile-backend harness (`internal/fuzzutil/hostile`)
  is vendored into the migrate module as `migrate/internal/hostile` (the migrate tool is a
  separate Go module and cannot import the root module's internal packages); its nine
  planted-defect self-tests pass unchanged. New direct-parser fuzz targets cover the pure
  parsers reached at first contact with an untrusted source: `splitjson.Object` (JSON-object
  explode for `--split-json`), `healthscan.ParsePolicyHCL` (the hand-rolled Vault ACL-policy
  HCL scanner, with a ReDoS watchdog), and `cmd.sanitizeSecretName` (provider name → Keyorix
  secret-name derivation). Each has a `scripts/fuzzing/targets.d` entry.
