### Fixed

- **A user with 10000 or more received shares (the cap) now gets a typed refusal from the secrets list, not a 500.** `GET /api/v1/secrets` answers `422 ShareListOverCap` (the body `GET /shares` already used) and gRPC `ListSecrets` answers `FailedPrecondition`, instead of `500 InternalError` / `Internal`. The list is still never shortened; `show_owned_only` avoids the refusal only for a caller with no role covering the listed scope. The 422 is documented on the operation.
