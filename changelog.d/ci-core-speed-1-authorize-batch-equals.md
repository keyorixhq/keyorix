### Testing

- `TestAuthorizeSecretsBatch_EqualsPerRow` runs its read-only comparison sweeps on four workers and pins the size of its matrix, so it is faster in CI and cannot shrink silently.
