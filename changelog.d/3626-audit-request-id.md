### Added
- **Audit rows record the request that wrote them.** `audit_events.request_id` stores the server's id of the HTTP request (the value returned in `X-Request-ID`), so an audit row can be joined with that request's log lines. It is NULL for scheduler, startup and gRPC writes and for rows from older replicas. The field is outside the tamper-evident hash chain and advisory: verification ignores it. The SIEM forwarder includes it. Schema epoch 6 (additive, compatibility floor unchanged). Design: `docs/specs/audit-request-id.md`.

### Changed
- **The server always mints the request id.** A caller's `X-Request-ID` is no longer adopted as the request id; it is logged as `client_request_id`, and the response's `X-Request-ID` carries the server's id.
