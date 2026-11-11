### Security
- **SCIM deactivation sent as a string is applied, not silently ignored.** Microsoft Entra ID sends `active` as the string `"False"` (`{"op":"Replace","path":"active","value":"False"}`); the strict boolean decode dropped it, the PATCH answered 200 and the user stayed active with its PATs and sessions. PATCH (path and path-less forms), PUT and POST now accept a JSON boolean or `"true"`/`"false"` in any case, and answer `400 invalidValue` for any other `active` value instead of a 200 that changes nothing.

### Fixed
- **Machine-token lifetime is bounded on both transports.** `expires_in_days` below 0 used to mint a token that never expires, and a huge value overflowed the expiry computation. HTTP and gRPC `IssueMachineToken` now share one core check (`core.MachineTokenExpiresAt`): 0 or omitted still means never expires, a negative value or one above 36500 days is `400` / `InvalidArgument` and mints nothing.
