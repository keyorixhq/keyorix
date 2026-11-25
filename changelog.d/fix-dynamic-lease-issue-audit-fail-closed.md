### Security

- Issuing a dynamic-secret lease now fails closed when its `dynamic_lease.issued` audit event cannot be written: the minted database credential is revoked and not returned (the request fails with the audit-unavailable error), instead of being handed out with no audit record (#4716).
