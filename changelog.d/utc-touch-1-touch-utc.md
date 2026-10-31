### Fixed
- **Passkey `last_used_at` is UTC on a non-UTC host.** The WebAuthn counter write stored the caller's zone; it now stores UTC (UTC-TOUCH-1).
