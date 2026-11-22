### Testing
- **`FuzzYAMLV4TypedDecode` for `internal/config`.** Checks no panic, bounded work, a deterministic
  typed decode and that an unknown top-level key is rejected under KnownFields (named, value not
  echoed). The go-yaml behaviour that a typed decode accepts an anchor cycle or a duplicate key
  under an ignored key is recorded as a triage entry in `docs/findings/`; its two inputs are seeds.
