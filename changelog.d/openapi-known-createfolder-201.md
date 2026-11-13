### Testing
- **Stateful OpenAPI fuzzer: record a second known undeclared success status.** `POST /api/v1/folders` returns 201 while `openapi.yaml` declares only 200, the same class as the already-recorded secret-template case. The fuzzer now logs it as a known finding instead of failing unrelated per-PR fuzz shards when it happens to create a folder. The spec fix remains open.
