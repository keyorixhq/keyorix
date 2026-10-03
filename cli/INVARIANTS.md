# cli — Invariants

Properties this module's code must preserve, per CLAUDE.md's "Spec first, independent tests, package
invariants": read this file before changing code in `cli/`. If you add or discover an invariant, add a
row here in the same PR. If a change has to break one, stop and ask the coordinator.

| ID | Invariant | Guard |
|----|-----------|-------|
| INV-1 | `keyorix-next run --derive-names` must never let a secret's NAME become a reserved/dangerous environment variable in the launched child process -- dynamic-linker, interpreter, or shell-control variables (`LD_*`, `DYLD_*`, `NODE_*`, `PYTHON*`, `PERL5*`, `BASH_*`, `GCONV_*`, `MALLOC_*`, `IFS`, `ENV`, `HOME`, `SHELL`, `PATH`, `RUBYOPT`, `GIT_SSH_COMMAND` — `cli/cmd/run.go`'s `dangerousEnvPrefixes`/`dangerousEnvExact`). Whoever can *name* a secret must not thereby control which env var it becomes (#1816). An explicit `--var NAME=secret-ref` mapping onto one of these names is a deliberate operator choice and is allowed (with a warning), unlike `--derive-names`, where the env var name was never a deliberate choice at all. | `cli/cmd/run_env_filter_test.go`: `TestIsDangerousEnvKey_ExactNames`, `TestIsDangerousEnvKey_PrefixFamilies`, `TestIsDangerousEnvKey_CaseVariantsAreNotFlagged`, `TestIsDangerousEnvKey_SimilarButSafeNames`, `TestDropDangerousEnvKeys_RemovesOnlyDangerousOnes`, `TestDropDangerousEnvKeys_RedProof`, `TestResolveChildEnvVars_DeriveNames_DropsReservedNames`, `TestResolveChildEnvVars_VarMapping_AllowsReservedNameExplicitly` (#2527) |
