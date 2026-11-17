### Testing

- Hostile-server fuzz harnesses (pgx, mysql, redis) now tell a hung driver call from a frozen fuzz process before reporting a bounded-time violation; test-only change.
