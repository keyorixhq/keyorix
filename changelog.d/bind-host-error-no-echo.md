### Fixed
- **A rejected `server.http.host` / `server.grpc.host` is no longer echoed in the startup error.** A `${VAR}`-expanded secret placed in a host field could reach the error text (found by `FuzzConfigLoadValidate`); the error now names only the field.
