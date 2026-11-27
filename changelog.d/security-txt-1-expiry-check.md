### Security

- **`security.txt` renewal check.** `scripts/check-security-txt-expiry.sh` fails when the `Expires` field of `docs/security/security.txt` has passed or is less than 30 days away, for a scheduled job; `Expires` moves to 2027-11-26.
