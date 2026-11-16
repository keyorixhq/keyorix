- **INV-SECUREFILES-write-fault-surfaced-no-fd-leak** Under a real filesystem fault
  (`SecureWriteFileSync`/`SecureOpenBeneath` against a read-only leaf, a symlinked or
  non-directory ancestor, or a path escaping the base) the write (c) surfaces a non-nil error
  and is never written through a symlink or outside the base; (d) a pre-existing target is left
  exactly its old content or exactly the new bytes, never a partial prefix (the open fails
  before `O_TRUNC` empties it); and (e) the per-component `O_NOFOLLOW` walk closes every
  directory descriptor it opened on every error path — a fd leak in a boot-time walk run per
  start would accumulate across restarts. Why: `securefiles.go` `SecureOpenBeneath` doc
  comment (the `unix.Close(dirFd)` on each walk step). Does NOT cover crash-atomicity of a
  SUCCESSFUL in-place write (SecureWriteFileSync is deliberately in-place; its callers add
  staging+rename). Guard: `FuzzSecureWriteUnderFault` (atomic_write_fault_fuzz_test.go).
