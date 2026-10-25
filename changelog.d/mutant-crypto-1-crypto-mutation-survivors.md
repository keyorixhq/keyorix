### Testing
- **internal/crypto mutation efficacy 88.2% to 98.8%.** New boundary tests for the KMS providers, Shamir, the multi-provider chain and the exec/file providers kill 36 of the gremlins survivors from #3612; the rest are listed with reasons in `internal/crypto/mutation_equivalents_test.go`. Test-only, no production change.
