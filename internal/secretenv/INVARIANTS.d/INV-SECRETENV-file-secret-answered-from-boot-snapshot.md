- **INV-SECRETENV-file-secret-answered-from-boot-snapshot** A non-key-material `*_FILE`
  secret that `config.Load` snapshots (`secretEnvNames`) is read once; every later consumer
  gets those bytes through `config.LookupSecretEnv`, never by calling `secretenv.Lookup`
  again. A caller outside `internal/config` and `internal/secretenv` that re-opens the file
  can use a file the permission and duplicate-secret checks never saw (the path retargeted
  between `Load` and use). Key material is the exception: it is read with
  `secretenv.LookupChecked`, which judges its own descriptor. Why: #3830
  (`resolveBootstrapToken`, `resolveVaultToken`), `docs/security-closures.d/CONFIG-TRUTH-1-BOOT-SNAPSHOT-SITES.tsv`.
  Guard: `TestNoLiveSecretenvLookupOfConfigSecrets` (`internal/config`, every non-test file
  in the repository outside the two exempt packages) and
  `TestNoLiveSecretenvLookupOfFileCapableVars` (`server`, report-only first day). Both
  recognise `secretenv.Lookup` called through the package import, with or without an alias,
  and a bare reference to it; they do not catch a dot-import or a hand-written
  `os.Getenv(name+"_FILE")` plus `os.ReadFile`. Behaviour proofs:
  `TestResolveBootstrapToken_AnsweredFromBootSnapshot`,
  `TestResolveVaultToken_AnsweredFromBootSnapshot` (`server`) and
  `TestSecretSnapshot_FileSwappedAfterLoad_AccessorsUseJudgedValue` (`internal/config`).
