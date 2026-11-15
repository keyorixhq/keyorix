## Relative key paths must be used from the config file's directory (#4249)

- A relative `storage.encryption.dek_path`, `salt_path` or key-provider path
  (`wrapped_key_path`, `shamir_share_files`, `file_path`) is now defined against the config
  file's directory, the base a relative `storage.database.path` already used. Key files are
  still opened from the working directory, so the server, and `admin encryption` commands,
  started from any other directory now refuse to start with
  `storage.encryption.dek_path "keys/dek.key" is relative, and relative key paths are resolved
  against the config file's directory (...)`, naming the key and the fix. Before, such a start
  used (or generated) another key set under the working directory and took another DEK lock,
  so a second server on the same database was not excluded.
- Nothing changes for an install started from its config directory
  (`KEYORIX_CONFIG_PATH=./keyorix.yaml`, the layout `admin init` writes) or one using absolute
  key paths (the container and Helm configs). The configured values are not rewritten, so
  existing backup archives restore as before.
- If a service manager starts Keyorix with `KEYORIX_CONFIG_PATH=/abs/keyorix.yaml` from
  another working directory, either set the key paths to absolute paths of the files the
  install has been using, or set the working directory to the config file's directory.
