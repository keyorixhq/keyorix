## `admin backup` refusals after a key rotation (#4104, #4105)

- On PostgreSQL, `keyorix-server admin backup` now refuses (non-zero exit, no archive) when its
  key directory's DEK is not the one the database's `dek.epoch` names. With several key directories
  (`storage.encryption.key_dir_lock: database`) that is every replica that has not received the new
  key set after a DEK rotation: distribute it (`docs/multi-replica-keys.md`) before backing up from
  that replica. Scripts that back up from an arbitrary replica right after a rotation should expect
  this refusal until the rotation is finished and distributed.
- `admin validate --posture` now reports a `[backup]` deviation while a key-rotation staging file
  (`<dek_path>.pending`, `<salt_path>.pending`) makes `admin backup` refuse, so its exit code is
  non-zero in that state.
