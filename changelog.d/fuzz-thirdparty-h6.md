### Testing
- **Deeper hostile-SERVER fuzz coverage of the third-party database drivers used against
  operator-configured targets.** New loopback harnesses drive the real pgx/v5,
  go-sql-driver/mysql and go-redis/v9 clients — exactly as the dynamic-secrets and
  rotation engines do — against a fuzzer-controlled server, with sound oracles: no panic
  escapes the driver's documented error path, bounded time/memory per hostile reply, and
  no credential reaches a host other than the configured one. Adds MySQL handshake/auth,
  COM_QUERY and prepared-statement response coverage plus a LOCAL INFILE refusal oracle
  (red/green); pgx COPY-subprotocol, NoticeResponse-flood and TLS-negotiation coverage;
  and go-redis ASK- and Sentinel-redirect egress red proofs alongside the existing MOVED
  one. All new targets are registered under `scripts/fuzzing/targets.d/`.
