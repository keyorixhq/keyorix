### Fixed
- **`docs/operator/startup-refusals.md`: the "Wrong master passphrase" entry now says
  what the key-file state looks like when you reach it.** Start-up checks the key set
  (`keys/dek.key`, `keys/kek.salt`, `keyset.manifest.json`) before it tries the passphrase,
  so a missing or mixed file is refused earlier with `key file consistency: ...` or the
  file-permission audit; the entry now links to those two and says that this message means
  the files are present and consistent.
