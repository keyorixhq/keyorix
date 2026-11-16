- **INV-ENCRYPTION-relative-key-path-one-base** A relative key-material path
  (`dek_path`, `salt_path`, a provider's `wrapped_key_path`, `shamir_share_files`,
  `file_path`) means one place for every process reading a config: the config's
  base directory (`EncryptionConfig.KeyPathBase`, set by `config.Load`, the base
  `storage.database.path` resolves against). `NewService` with a base directory
  that is the working directory (`"."` or `os.Getwd()`) records
  `CheckRelativeKeyPathBase`'s refusal when the working directory is not that
  base (another base directory, such as backup's staging copy, is the caller's
  choice and is not judged), and `AcquireExclusiveKeyLock` and `Initialize` return
  it before opening the DEK lock or a key file, so two servers on one config
  started from two directories cannot hold two different `dek.lock` files. The
  configured values are never rewritten (backup archives record them). Why:
  #4249. Guard: `relative_key_path_lock_test.go`
  (`TestRelativeDEKPath_TwoServersFromDifferentCwd_SecondIsRefused`, control
  `TestRelativeDEKPath_TwoServersFromConfigDir_SecondRefusedByLock`),
  `internal/config/key_paths_test.go`. **Not covered**: `keyfiles.Registry`
  callers (the permission fixer, `admin restore`, the restore journal), which
  still resolve against the working directory.
