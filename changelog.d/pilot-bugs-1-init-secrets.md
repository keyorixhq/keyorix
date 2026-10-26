### Fixed
- **`init-secrets.sh` no longer half-initialises when run as uid 1001 (#3522).** A user whose uid is the server container's uid now gets the refusal before anything is written (no secrets, no `.env` edit), instead of the files being created and the script then exiting 1.
