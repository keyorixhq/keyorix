### Fixed
- **`keyorix secret import --format vault` no longer imports YAML null or nested values as text.**
  A secret whose value was `~`/`null`/empty (`value:`) was stored as the literal text `<nil>`, and a
  mapping or sequence value as Go map/slice text. The import now fails with an error that names the
  path and field (never the value) and imports nothing from the file. Strings, numbers and booleans
  are unchanged; a quoted `"~"` or `"null"` is still the literal string.
