### Testing
- **A relative `KEYORIX_TOKEN_FILE` has a CLI journey.** `TestJourney_TokenFileRelativePath` drives `./token` (0600, in the CLI's working directory) against a real server, and checks that a relative path to a missing file fails with exit 3 without echoing the path (#3564).
- **The "variable unset" env-expansion test really unsets the variable.** `t.Setenv(name, "")` leaves it set-but-empty; `TestLoadExpandsEnvVarFallsBackToDefaultWhenUnset` now unsets it and both it and the set-but-empty test assert which state they are in.
