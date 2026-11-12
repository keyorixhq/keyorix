### Testing
- **Hostile-source fuzzing for the `keyorix-migrate` tool and its `vault scan` health
  assessment.** The record-and-mutate hostile-backend harness (`internal/fuzzutil/hostile`)
  is vendored into the migrate module as `migrate/internal/hostile` (the migrate tool is a
  separate Go module and cannot import the root module's internal packages); its nine
  planted-defect self-tests pass unchanged. New fuzz targets cover the untrusted inputs
  reached at first contact with a customer source: three direct parsers — `splitjson.Object`
  (JSON-object explode for `--split-json`), `healthscan.ParsePolicyHCL` (the hand-rolled Vault
  ACL-policy HCL scanner, with a ReDoS watchdog), and `cmd.sanitizeSecretName` (provider name →
  Keyorix secret-name derivation) — and three hostile-server targets driving the real client
  code against fake backends whose responses are fuzz-mutated: `vaultsource.Client.Walk` (the
  recursive KV reader / import write path), the whole `healthscan.Run` check suite (the paid
  `vault scan` assessment) with its rendered reports, and `awssource.Client.List` through the
  real aws-sdk-go-v2 client (SDK `BaseEndpoint` seam). Oracles: no panic/hang/alloc-blowup,
  secret values and credentials never leak into an error/log/report, derived names/paths are
  normalised, redirects are never followed, and a non-success response is never a truncated
  success. Each target has a `scripts/fuzzing/targets.d` entry; `splitjson` and `vaultsource`
  gain `INVARIANTS.md` + fragment entries for the invariants the targets enforce.
