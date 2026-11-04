### Fixed
- **`GET /api/v1/secrets` and gRPC `ListSecrets` answer a caller whose share list is at the 10000-row cap with a typed refusal, not a 500.** HTTP answers `422 ShareListOverCap` (the body `GET /api/v1/shares` already uses), gRPC `FailedPrecondition`; `openapi.yaml` documents the 422 and the web and Go client types are regenerated. Previously both answered 500 / `Internal`.
