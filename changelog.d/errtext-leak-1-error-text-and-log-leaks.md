### Security
- **Server text no longer reaches connector, fetcher and access-log output.** The Azure Key Vault connector answers a 2xx reply other than 200 with a fixed message and the status code instead of the response headers and body (#4061). The Kubernetes sync fetcher reports a response that does not decode (for example a malformed `expiration`) with fixed text instead of the decoder's error, which quoted the server's value (#4062). The access log redacts the whole token segment of `GET /auth/setup/{token}` (and the invite and password-reset look-alikes), including a token that contains an encoded slash (`%2F`), whose tail used to be logged (#4045).

### Fixed
- **Vault token TTL check reports a failed body read.** `CheckTokenTTL` discarded the read error, so a connection that died after a complete root-token reply returned a TTL of 0 with no error, which looks like a healthy never-expiring token. It now returns the (wrapped, body-free) error (#4063).

### Testing
- **Webhook delivery log regression test.** A failed delivery to a generic webhook whose URL carries a path token never logs the token, for a transport error, a retried 5xx and a permanent 4xx. The leak itself (#3426) was already fixed on main.
