### Deprecated
- **`server.http.keepalive.*` is deprecated and ignored.** Only `server.grpc.keepalive` was ever read; the eight keys under `server.http.keepalive` parsed and did nothing. Setting the block now prints a start-up warning. Remove it from `keyorix.yaml`: it is deleted after one minor release. No configuration that `keyorix-server admin init` writes contains it.
